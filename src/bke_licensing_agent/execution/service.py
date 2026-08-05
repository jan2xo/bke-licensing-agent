"""Product-agnostic, integrity-bound process execution."""

import hashlib
import os
import subprocess
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable, Sequence

from ..licensing.launch_authorization import AuthorizationDecision
from ..manifest.models import Manifest


class LaunchPolicyError(Exception):
    """Base class for fail-closed launch errors."""


class ExecutionState(StrEnum):
    LAUNCHED = "launched"
    ALREADY_RUNNING = "already_running"
    DENIED = "denied"
    EXECUTABLE_MISSING = "executable_missing"
    EXECUTABLE_INVALID = "executable_invalid"
    EXECUTABLE_MODIFIED = "executable_modified"
    PATH_ESCAPE = "path_escape"
    SYMLINK_ESCAPE = "symlink_escape"
    STALE_AUTHORIZATION = "stale_authorization"
    AUTHORIZATION_EXPIRED = "authorization_expired"
    LAUNCH_FAILED = "launch_failed"


class ProcessState(StrEnum):
    STARTING = "starting"
    RUNNING = "running"
    EXITED = "exited"
    CRASHED = "crashed"
    LAUNCH_FAILED = "launch_failed"
    TERMINATED = "terminated"


@dataclass(frozen=True)
class ProcessRecord:
    product_id: str
    process_id: int
    state: ProcessState
    start_time: datetime | None = None
    exit_time: datetime | None = None
    exit_code: int | None = None
    correlation_id: str | None = None


@dataclass(frozen=True)
class ArtifactMetadata:
    product_id: str
    version: str
    relative_path: str
    sha256: str


@dataclass(frozen=True)
class ExecutionResult:
    state: ExecutionState
    product_id: str
    pid: int | None = None
    executable: str | None = None
    sha256: str | None = None
    started_at: datetime | None = None
    reason: str = ""


class LaunchExecutionService:
    def __init__(self, audit: Any | None = None,
                 generation_current: Callable[[AuthorizationDecision], bool] | None = None,
                 popen: Callable[..., subprocess.Popen] = subprocess.Popen,
                 before_process: Callable[[Path], None] | None = None):
        self.audit = audit
        self.generation_current = generation_current or (lambda _decision: True)
        self.popen = popen
        self.before_process = before_process or (lambda _path: None)
        self._lock = threading.Condition()
        self._inflight: dict[str, threading.Event] = {}
        self._results: dict[str, ExecutionResult] = {}
        self._processes: dict[str, subprocess.Popen] = {}
        self._records: dict[str, ProcessRecord] = {}

    def launch(self, manifest: Manifest, product_root: Path,
               decision: AuthorizationDecision, artifact: ArtifactMetadata,
               arguments: Sequence[str] = (), environment: dict[str, str] | None = None,
               installation_id: str | None = None, device_id: str | None = None,
               installation_generation: int | None = None) -> ExecutionResult:
        key = manifest.productId
        with self._lock:
            if key in self._processes and self._processes[key].poll() is None:
                return self._finish(ExecutionResult(ExecutionState.ALREADY_RUNNING, key))
            flight = self._inflight.get(key)
            if flight is None:
                flight = threading.Event()
                self._inflight[key] = flight
                owner = True
            else:
                owner = False
        if not owner:
            flight.wait()
            return self._results[key]
        try:
            result = self._launch_once(manifest, product_root, decision, artifact, arguments, environment,
                                       installation_id, device_id, installation_generation)
            with self._lock:
                self._results[key] = result
            return result
        finally:
            with self._lock:
                self._inflight.pop(key, None)
                flight.set()

    def _launch_once(self, manifest, product_root, decision, artifact, arguments, environment,
                     installation_id, device_id, installation_generation):
        if not manifest.is_validated or not decision.allowed:
            return self._finish(ExecutionResult(ExecutionState.DENIED, manifest.productId, reason="Authorization denied"))
        if decision.product_id != manifest.productId or artifact.product_id != manifest.productId or artifact.version != manifest.version:
            return self._finish(ExecutionResult(ExecutionState.DENIED, manifest.productId, reason="Binding mismatch"))
        if installation_id is not None and decision.installation_id != installation_id:
            return self._finish(ExecutionResult(ExecutionState.DENIED, manifest.productId, reason="Installation mismatch"))
        if device_id is not None and decision.device_id != device_id:
            return self._finish(ExecutionResult(ExecutionState.DENIED, manifest.productId, reason="Device mismatch"))
        if installation_generation is not None and decision.installation_generation != installation_generation:
            return self._finish(ExecutionResult(ExecutionState.DENIED, manifest.productId, reason="Installation generation mismatch"))
        if decision.product_version is not None and decision.product_version != manifest.version:
            return self._finish(ExecutionResult(ExecutionState.DENIED, manifest.productId, reason="Version mismatch"))
        if decision.expires_at is not None and datetime.now(timezone.utc) >= decision.expires_at:
            return self._finish(ExecutionResult(ExecutionState.AUTHORIZATION_EXPIRED, manifest.productId))
        if not self.generation_current(decision):
            return self._finish(ExecutionResult(ExecutionState.STALE_AUTHORIZATION, manifest.productId))
        root = Path(product_root).resolve()
        declared = Path(manifest.entryPoint)
        if declared.is_absolute() or ".." in declared.parts:
            return self._finish(ExecutionResult(ExecutionState.PATH_ESCAPE, manifest.productId))
        executable = (root / declared).resolve()
        if root not in executable.parents:
            return self._finish(ExecutionResult(ExecutionState.SYMLINK_ESCAPE, manifest.productId))
        if not executable.exists():
            return self._finish(ExecutionResult(ExecutionState.EXECUTABLE_MISSING, manifest.productId))
        if not executable.is_file():
            return self._finish(ExecutionResult(ExecutionState.EXECUTABLE_INVALID, manifest.productId))
        digest = hashlib.sha256(executable.read_bytes()).hexdigest()
        if artifact.relative_path.replace("\\", "/") != manifest.entryPoint.replace("\\", "/"):
            return self._finish(ExecutionResult(ExecutionState.EXECUTABLE_INVALID, manifest.productId))
        if digest.lower() != artifact.sha256.lower():
            return self._finish(ExecutionResult(ExecutionState.EXECUTABLE_MODIFIED, manifest.productId, sha256=digest))
        if not self.generation_current(decision):
            return self._finish(ExecutionResult(ExecutionState.STALE_AUTHORIZATION, manifest.productId))
        self.before_process(executable)
        final_digest = hashlib.sha256(executable.read_bytes()).hexdigest()
        if final_digest.lower() != artifact.sha256.lower():
            return self._finish(ExecutionResult(ExecutionState.EXECUTABLE_MODIFIED, manifest.productId, sha256=final_digest))
        env = os.environ.copy()
        if environment:
            env.update(environment)
        try:
            self._audit("launch_requested", manifest.productId, decision)
            process = self.popen([str(executable), *arguments], cwd=str(root), env=env, shell=False)
        except (OSError, ValueError) as exc:
            self._audit("launch_failed", manifest.productId, decision)
            return self._finish(ExecutionResult(ExecutionState.LAUNCH_FAILED, manifest.productId, executable=str(executable), sha256=digest, reason=str(exc)))
        with self._lock:
            self._processes[manifest.productId] = process
            record = ProcessRecord(manifest.productId, process.pid, ProcessState.RUNNING,
                                   datetime.now(timezone.utc), correlation_id=decision.correlation_id)
            self._records[manifest.productId] = record
        self._audit("launch_started", manifest.productId, decision)
        self._audit("process_running", manifest.productId, decision)
        return self._finish(ExecutionResult(ExecutionState.LAUNCHED, manifest.productId, process.pid, str(executable), digest, datetime.now(timezone.utc)))

    def terminate(self, product_id: str) -> bool:
        with self._lock:
            process = self._processes.get(product_id)
        if process is None or process.poll() is not None:
            return False
        process.terminate()
        with self._lock:
            record = self._records.get(product_id)
            if record:
                self._records[product_id] = ProcessRecord(product_id, record.process_id,
                    ProcessState.TERMINATED, record.start_time, datetime.now(timezone.utc),
                    process.poll(), record.correlation_id)
        self._audit("process_terminated", product_id, None)
        return True

    def process_status(self, product_id: str) -> ProcessRecord | None:
        with self._lock:
            process = self._processes.get(product_id)
            record = self._records.get(product_id)
        if process is None or record is None or process.poll() is None:
            return record
        if record.state is ProcessState.TERMINATED:
            return record
        code = process.poll()
        state = ProcessState.EXITED if code == 0 else ProcessState.CRASHED
        updated = ProcessRecord(product_id, record.process_id, state, record.start_time,
                                datetime.now(timezone.utc), code, record.correlation_id)
        with self._lock:
            self._records[product_id] = updated
        self._audit("process_exited" if code == 0 else "process_crashed", product_id, None)
        return updated

    def _audit(self, event: str, product_id: str, decision: AuthorizationDecision | None) -> None:
        if self.audit:
            try:
                self.audit.record_audit_event(event, event, product_id=product_id,
                    activation_id=decision.correlation_id if decision else None)
            except Exception:
                return

    def _finish(self, result: ExecutionResult) -> ExecutionResult:
        if self.audit:
            try:
                self.audit.record_audit_event("launch", result.state.value, product_id=result.product_id)
            except Exception:
                if result.state is ExecutionState.LAUNCHED:
                    return ExecutionResult(ExecutionState.LAUNCH_FAILED, result.product_id,
                                           result.pid, result.executable, result.sha256,
                                           result.started_at, "Launch succeeded but audit persistence failed")
        return result
