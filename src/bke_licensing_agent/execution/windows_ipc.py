"""Windows-only named-pipe peer authentication adapter."""

import ctypes
import hashlib
import os
from ctypes import wintypes
from pathlib import Path

from .module_launch import PeerIdentity


class WindowsIpcUnavailable(RuntimeError):
    pass


def _modules():
    if os.name != "nt":
        raise WindowsIpcUnavailable("Windows named-pipe authentication is Windows-only")
    import win32api, win32con, win32pipe, win32process, win32security
    import pywintypes
    return win32api, win32con, win32pipe, win32process, win32security, pywintypes


def current_user_and_system_security_attributes():
    """DACL granting pipe access only to the current user SID and LocalSystem."""
    win32api, win32con, _, _, win32security, pywintypes = _modules()
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    user_sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    system_sid = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid, None)
    dacl = win32security.ACL()
    access = win32con.GENERIC_READ | win32con.GENERIC_WRITE
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, access, user_sid)
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, access, system_sid)
    descriptor = win32security.SECURITY_DESCRIPTOR()
    descriptor.SetSecurityDescriptorDacl(1, dacl, 0)
    attributes = pywintypes.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = descriptor
    return attributes


def _query_full_process_image_name(process_handle) -> str:
    """Resolve a process image path using the stable Win32 API directly.

    pywin32 does not expose QueryFullProcessImageName consistently across runner
    versions, so the IPC trust boundary uses kernel32 with the already-opened
    PROCESS_QUERY_LIMITED_INFORMATION handle instead of depending on that wrapper.
    """
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    query = kernel32.QueryFullProcessImageNameW
    query.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    query.restype = wintypes.BOOL

    size = wintypes.DWORD(32768)
    buffer = ctypes.create_unicode_buffer(size.value)
    if not query(wintypes.HANDLE(int(process_handle)), 0, buffer, ctypes.byref(size)):
        raise ctypes.WinError(ctypes.get_last_error())
    return buffer.value


def peer_identity_from_pipe(pipe_handle) -> PeerIdentity:
    win32api, win32con, win32pipe, win32process, _, _ = _modules()
    pid = int(win32pipe.GetNamedPipeClientProcessId(pipe_handle))
    access = win32con.PROCESS_QUERY_LIMITED_INFORMATION | win32con.SYNCHRONIZE
    process = win32api.OpenProcess(access, False, pid)
    try:
        path = _query_full_process_image_name(process)
        created = win32process.GetProcessTimes(process)["CreationTime"]
        creation_time = int(created.timestamp() * 10_000_000)
        digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        return PeerIdentity(pid, path, digest, creation_time)
    finally:
        win32api.CloseHandle(process)
