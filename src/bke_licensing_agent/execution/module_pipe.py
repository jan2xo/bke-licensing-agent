"""Versioned per-user Windows named-pipe server for enterprise module launch."""

import hashlib
import json
import os
import struct
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from .module_launch import BundlePolicy, EnterpriseModuleLaunchService, ModuleLaunchDenied
from .service import ArtifactMetadata
from ..licensing.launch_authorization import AuthorizationDecision
from ..manifest.models import Manifest

SCHEMA = "bke.module-ipc.v1"
MAX_MESSAGE_BYTES = 16 * 1024
DEFAULT_IO_TIMEOUT_SECONDS = 5.0


def per_user_pipe_name() -> str:
    if os.name != "nt":
        raise RuntimeError("Module IPC is Windows-only")
    import win32api, win32con, win32security
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    sid = win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token, win32security.TokenUser)[0])
    suffix = hashlib.sha256(sid.encode("ascii")).hexdigest()[:16]
    return rf"\\.\pipe\bke-licensing-agent-{suffix}-module-v1"


@dataclass(frozen=True)
class ModuleLaunchContext:
    policy: BundlePolicy
    target_manifest: Manifest
    target_root: Path
    target_artifact: ArtifactMetadata


class EnterpriseModulePipeDispatcher:
    def __init__(self, service: EnterpriseModuleLaunchService,
                 contexts: Mapping[str, ModuleLaunchContext],
                 authorize_source: Callable[[BundlePolicy, str], AuthorizationDecision]):
        self._service = service
        self._contexts = dict(contexts)
        self._authorize_source = authorize_source

    def __call__(self, pipe_handle: object, request: dict[str, object]) -> dict[str, object]:
        operation = request.get("operation")
        if operation == "launch":
            policy_id = request.get("policy_id")
            installation_id = request.get("installation_id")
            if not isinstance(installation_id, str) or not installation_id:
                raise ModuleLaunchDenied("invalid_source_binding")
            context = self._contexts.get(str(policy_id))
            if context is None:
                raise ModuleLaunchDenied("unknown_policy")
            source_decision = self._authorize_source(context.policy, installation_id)
            pid = self._service.launch(context.policy, pipe_handle, source_decision,
                context.target_manifest, context.target_root, context.target_artifact)
            return {"child_pid": pid, "policy_id": context.policy.policy_id}
        if operation == "redeem":
            session = self._service.redeem(pipe_handle)
            return {"enterprise": True, "policy_id": session.policy_id,
                    "expires_at": session.expires_at.isoformat()}
        raise ModuleLaunchDenied("unsupported_operation")


class ModuleLaunchPipeServer:
    def __init__(self, dispatcher: Callable[[object, dict[str, object]], dict[str, object]],
                 pipe_name: str | None = None, io_timeout: float = DEFAULT_IO_TIMEOUT_SECONDS):
        self.dispatcher, self.pipe_name, self.io_timeout = dispatcher, pipe_name, io_timeout
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self.pipe_name = self.pipe_name or per_user_pipe_name()
        self._thread = threading.Thread(target=self._serve, name="bke-module-ipc", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if os.name == "nt" and self.pipe_name:
            try:
                import win32con, win32file
                handle = win32file.CreateFile(self.pipe_name, win32con.GENERIC_READ | win32con.GENERIC_WRITE,
                    0, None, win32con.OPEN_EXISTING, 0, None)
                win32file.CloseHandle(handle)
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout)

    def _serve(self) -> None:
        import win32con, win32file, win32pipe
        from .windows_ipc import current_user_and_system_security_attributes
        while not self._stop.is_set():
            pipe = win32pipe.CreateNamedPipe(self.pipe_name, win32pipe.PIPE_ACCESS_DUPLEX,
                win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT,
                1, MAX_MESSAGE_BYTES, MAX_MESSAGE_BYTES, int(self.io_timeout * 1000),
                current_user_and_system_security_attributes())
            try:
                try:
                    win32pipe.ConnectNamedPipe(pipe, None)
                except Exception as exc:
                    if getattr(exc, "winerror", None) != 535:
                        raise
                if self._stop.is_set():
                    continue
                request = self._read_request(pipe)
                response = self._dispatch(pipe, request)
                self._write(pipe, response)
                win32file.FlushFileBuffers(pipe)
            except Exception:
                try:
                    self._write(pipe, self._response("unknown", False, error="transport_error"))
                except Exception:
                    pass
            finally:
                try:
                    win32pipe.DisconnectNamedPipe(pipe)
                except Exception:
                    pass
                win32file.CloseHandle(pipe)

    def _dispatch(self, pipe, request):
        request_id = request.get("request_id") if isinstance(request, dict) else None
        if (not isinstance(request, dict) or request.get("schema") != SCHEMA or
                not isinstance(request_id, str) or not request_id or len(request_id) > 128):
            return self._response(str(request_id or "unknown"), False, error="invalid_request")
        try:
            return self._response(request_id, True, result=self.dispatcher(pipe, request))
        except ModuleLaunchDenied as exc:
            return self._response(request_id, False, error=str(exc))
        except Exception:
            return self._response(request_id, False, error="internal_error")

    def _read_request(self, pipe):
        header = self._read_exact(pipe, 4)
        size = struct.unpack("!I", header)[0]
        if size < 2 or size > MAX_MESSAGE_BYTES:
            raise ValueError("message_size")
        return json.loads(self._read_exact(pipe, size).decode("utf-8"))

    def _read_exact(self, pipe, size):
        import win32file, win32pipe
        deadline, chunks, remaining = time.monotonic() + self.io_timeout, [], size
        while remaining:
            if time.monotonic() >= deadline:
                raise TimeoutError("pipe_read_timeout")
            available = win32pipe.PeekNamedPipe(pipe, 0)[1]
            if not available:
                time.sleep(0.01)
                continue
            _, data = win32file.ReadFile(pipe, min(remaining, available))
            chunks.append(data)
            remaining -= len(data)
        return b"".join(chunks)

    @staticmethod
    def _write(pipe, response):
        import win32file
        payload = json.dumps(response, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(payload) > MAX_MESSAGE_BYTES:
            raise ValueError("response_size")
        win32file.WriteFile(pipe, struct.pack("!I", len(payload)) + payload)

    @staticmethod
    def _response(request_id, ok, *, result=None, error=None):
        value = {"schema": SCHEMA, "request_id": request_id, "ok": ok}
        if ok:
            value["result"] = result or {}
        else:
            value["error"] = error or "denied"
        return value
