"""Safe composition of the packaged, Agent-owned native License Center."""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from .service import LicenseCenterOutcome, OpenLicenseCenterRequest, OpenLicenseCenterResult


def _run_windows_interactive(
    arguments: Sequence[str], *, shell: bool = False, check: bool = False
) -> subprocess.CompletedProcess[str]:
    """Launch License Center in the active interactive Windows desktop.

    The installed Agent runs as LocalSystem under the Windows SCM. Starting the
    UI with ordinary ``subprocess.run`` from that service would place it in the
    non-interactive service session. Instead, obtain the token for the active
    console session and create the process on ``winsta0\\default``.

    This helper deliberately fails closed. It never falls back to launching the
    License Center invisibly in Session 0.
    """
    if shell or check:
        raise ValueError("interactive License Center launch requires shell=False and check=False")
    if not arguments:
        raise OSError("License Center command is empty")

    # Keep all Windows-only imports inside the Windows execution path so the
    # package remains importable and testable on macOS/Linux.
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    userenv = ctypes.WinDLL("userenv", use_last_error=True)
    wtsapi32 = ctypes.WinDLL("wtsapi32", use_last_error=True)

    class STARTUPINFO(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("lpReserved", wintypes.LPWSTR),
            ("lpDesktop", wintypes.LPWSTR),
            ("lpTitle", wintypes.LPWSTR),
            ("dwX", wintypes.DWORD),
            ("dwY", wintypes.DWORD),
            ("dwXSize", wintypes.DWORD),
            ("dwYSize", wintypes.DWORD),
            ("dwXCountChars", wintypes.DWORD),
            ("dwYCountChars", wintypes.DWORD),
            ("dwFillAttribute", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("wShowWindow", wintypes.WORD),
            ("cbReserved2", wintypes.WORD),
            ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
            ("hStdInput", wintypes.HANDLE),
            ("hStdOutput", wintypes.HANDLE),
            ("hStdError", wintypes.HANDLE),
        ]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("hProcess", wintypes.HANDLE),
            ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD),
            ("dwThreadId", wintypes.DWORD),
        ]

    kernel32.WTSGetActiveConsoleSessionId.restype = wintypes.DWORD
    wtsapi32.WTSQueryUserToken.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    wtsapi32.WTSQueryUserToken.restype = wintypes.BOOL
    userenv.CreateEnvironmentBlock.argtypes = [ctypes.POINTER(wintypes.LPVOID), wintypes.HANDLE, wintypes.BOOL]
    userenv.CreateEnvironmentBlock.restype = wintypes.BOOL
    userenv.DestroyEnvironmentBlock.argtypes = [wintypes.LPVOID]
    userenv.DestroyEnvironmentBlock.restype = wintypes.BOOL
    advapi32.CreateProcessAsUserW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.BOOL,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPCWSTR,
        ctypes.POINTER(STARTUPINFO),
        ctypes.POINTER(PROCESS_INFORMATION),
    ]
    advapi32.CreateProcessAsUserW.restype = wintypes.BOOL
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    session_id = kernel32.WTSGetActiveConsoleSessionId()
    if session_id == 0xFFFFFFFF:
        raise OSError("No active Windows console session is available for License Center")

    token = wintypes.HANDLE()
    environment = wintypes.LPVOID()
    process_info = PROCESS_INFORMATION()
    environment_created = False

    def windows_error(message: str) -> OSError:
        code = ctypes.get_last_error()
        return OSError(code, f"{message} (Windows error {code})")

    try:
        if not wtsapi32.WTSQueryUserToken(session_id, ctypes.byref(token)):
            raise windows_error("Could not obtain the active Windows user token")

        if not userenv.CreateEnvironmentBlock(ctypes.byref(environment), token, False):
            raise windows_error("Could not build the active Windows user environment")
        environment_created = True

        startup = STARTUPINFO()
        startup.cb = ctypes.sizeof(STARTUPINFO)
        startup.lpDesktop = "winsta0\\default"

        command_line = subprocess.list2cmdline([str(value) for value in arguments])
        mutable_command = ctypes.create_unicode_buffer(command_line)
        executable = str(arguments[0])
        working_directory = str(Path(executable).resolve().parent)

        CREATE_UNICODE_ENVIRONMENT = 0x00000400
        if not advapi32.CreateProcessAsUserW(
            token,
            executable,
            mutable_command,
            None,
            None,
            False,
            CREATE_UNICODE_ENVIRONMENT,
            environment,
            working_directory,
            ctypes.byref(startup),
            ctypes.byref(process_info),
        ):
            raise windows_error("Could not launch License Center in the active Windows session")

        # The Agent endpoint is typed around the License Center terminal exit
        # code, so wait for the UI to finish and preserve the established
        # 0=refreshed, 2=cancelled, 3=activation-failed mapping.
        WAIT_FAILED = 0xFFFFFFFF
        INFINITE = 0xFFFFFFFF
        if kernel32.WaitForSingleObject(process_info.hProcess, INFINITE) == WAIT_FAILED:
            raise windows_error("Could not wait for License Center completion")

        exit_code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(process_info.hProcess, ctypes.byref(exit_code)):
            raise windows_error("Could not read License Center exit status")

        return subprocess.CompletedProcess(
            args=[str(value) for value in arguments],
            returncode=int(exit_code.value),
        )
    finally:
        if process_info.hThread:
            kernel32.CloseHandle(process_info.hThread)
        if process_info.hProcess:
            kernel32.CloseHandle(process_info.hProcess)
        if environment_created and environment:
            userenv.DestroyEnvironmentBlock(environment)
        if token:
            kernel32.CloseHandle(token)


class NativeLicenseCenterLauncher:
    """Launch the sibling packaged UI and wait for its typed terminal outcome."""

    def __init__(
        self,
        executable: Path | None = None,
        *,
        runner: Callable[..., object] | None = None,
    ):
        self.executable = executable or self._default_executable()
        if runner is not None:
            self.runner = runner
        elif sys.platform == "win32":
            self.runner = _run_windows_interactive
        else:
            self.runner = subprocess.run

    @staticmethod
    def _default_executable() -> Path:
        name = "bke-license-center.exe" if sys.platform == "win32" else "bke-license-center"
        agent_dir = Path(sys.executable).resolve().parent

        # Windows service payload: {app}/service/<service.exe>
        # Windows GUI payload:     {app}/license-center/bke-license-center.exe
        # macOS/Linux frozen layout continues to use bke-license-center/.
        if sys.platform == "win32":
            candidates = (
                agent_dir / name,
                agent_dir.parent / "license-center" / name,
                agent_dir.parent / "bke-license-center" / name,
            )
        else:
            candidates = (
                agent_dir / name,
                agent_dir.parent / "bke-license-center" / name,
            )

        return next((candidate for candidate in candidates if candidate.is_file()), candidates[0])

    def __call__(self, request: OpenLicenseCenterRequest) -> OpenLicenseCenterResult:
        if not self.executable.is_file():
            return self._result(request, LicenseCenterOutcome.AGENT_UNAVAILABLE,
                                "native License Center is not installed")
        arguments: Sequence[str] = (
            str(self.executable), "--product-id", request.product_id,
            "--product-version", request.product_version,
            "--installation-id", request.safe_context["installation_id"] if request.safe_context else "",
            "--correlation-id", request.correlation_id,
            "--action", request.action.value,
        )
        try:
            completed = self.runner(arguments, shell=False, check=False)
        except (OSError, ValueError):
            return self._result(request, LicenseCenterOutcome.FAILED,
                                "native License Center could not be started")
        outcomes = {
            0: LicenseCenterOutcome.AUTHORIZATION_REFRESHED,
            2: LicenseCenterOutcome.CANCELLED,
            3: LicenseCenterOutcome.ACTIVATION_FAILED,
        }
        outcome = outcomes.get(completed.returncode, LicenseCenterOutcome.FAILED)
        return self._result(request, outcome, "" if completed.returncode in outcomes else "native License Center failed")

    @staticmethod
    def _result(request, outcome, reason):
        return OpenLicenseCenterResult(
            outcome=outcome, reason=reason, product_id=request.product_id,
            correlation_id=request.correlation_id,
            authorization_changed=outcome is LicenseCenterOutcome.AUTHORIZATION_REFRESHED,
        )
