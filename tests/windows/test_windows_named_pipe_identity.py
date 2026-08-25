import os
import threading

import pytest

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows native IPC test")


def test_named_pipe_dacl_and_real_peer_pid():
    import win32con, win32file, win32pipe, win32security
    from bke_licensing_agent.execution.windows_ipc import current_user_and_system_security_attributes, peer_identity_from_pipe
    name = rf"\\.\pipe\bke-agent-test-{os.getpid()}"
    attrs = current_user_and_system_security_attributes()
    pipe = win32pipe.CreateNamedPipe(name, win32pipe.PIPE_ACCESS_DUPLEX,
        win32pipe.PIPE_TYPE_MESSAGE|win32pipe.PIPE_READMODE_MESSAGE|win32pipe.PIPE_WAIT,1,4096,4096,5000,attrs)
    client=[]
    def connect(): client.append(win32file.CreateFile(name,win32con.GENERIC_READ|win32con.GENERIC_WRITE,0,None,win32con.OPEN_EXISTING,0,None))
    thread=threading.Thread(target=connect); thread.start(); win32pipe.ConnectNamedPipe(pipe,None); thread.join(5)
    try:
        peer=peer_identity_from_pipe(pipe)
        assert peer.pid==os.getpid() and peer.creation_time>0 and len(peer.sha256)==64
        dacl=attrs.SECURITY_DESCRIPTOR.GetSecurityDescriptorDacl()
        assert dacl.GetAceCount()==2
        everyone=win32security.CreateWellKnownSid(win32security.WinWorldSid,None)
        assert all(dacl.GetAce(i)[2] != everyone for i in range(dacl.GetAceCount()))
    finally:
        if client: win32file.CloseHandle(client[0])
        win32file.CloseHandle(pipe)
