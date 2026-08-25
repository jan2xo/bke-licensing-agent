import os
import json
import struct
import threading
import time

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


def test_versioned_pipe_server_end_to_end_and_explicit_denial():
    import win32con, win32file, win32pipe
    from bke_licensing_agent.execution.module_pipe import ModuleLaunchPipeServer, SCHEMA, per_user_pipe_name
    from bke_licensing_agent.execution.windows_ipc import peer_identity_from_pipe
    seen=[]
    def dispatch(pipe, request):
        peer=peer_identity_from_pipe(pipe); seen.append(peer)
        if request["operation"] != "launch":
            from bke_licensing_agent.execution.module_launch import ModuleLaunchDenied
            raise ModuleLaunchDenied("unsupported_operation")
        return {"child_pid": 123, "policy_id": request["policy_id"]}
    server=ModuleLaunchPipeServer(dispatch, io_timeout=2); server.start()
    deadline=time.time()+5
    while True:
        try:
            win32pipe.WaitNamedPipe(per_user_pipe_name(),200); break
        except Exception:
            if time.time()>=deadline: raise
    def request(value):
        handle=win32file.CreateFile(per_user_pipe_name(),win32con.GENERIC_READ|win32con.GENERIC_WRITE,0,None,win32con.OPEN_EXISTING,0,None)
        try:
            payload=json.dumps(value,separators=(",", ":")).encode(); win32file.WriteFile(handle,struct.pack("!I",len(payload))+payload)
            _,header=win32file.ReadFile(handle,4); size=struct.unpack("!I",header)[0]; _,body=win32file.ReadFile(handle,size)
            return json.loads(body)
        finally: win32file.CloseHandle(handle)
    try:
        allowed=request({"schema":SCHEMA,"operation":"launch","request_id":"one","policy_id":"policy"})
        denied=request({"schema":SCHEMA,"operation":"magic","request_id":"two"})
        assert allowed=={"schema":SCHEMA,"request_id":"one","ok":True,"result":{"child_pid":123,"policy_id":"policy"}}
        assert denied["ok"] is False and denied["error"]=="unsupported_operation"
        assert len(seen)==2 and all(peer.pid==os.getpid() for peer in seen)
    finally: server.stop()
