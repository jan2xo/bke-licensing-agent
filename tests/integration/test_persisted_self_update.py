import pytest
import hashlib, json, subprocess, sys, time
from pathlib import Path

def executable(path:Path, code:int, pid_file:Path, marker:Path):
    body = [
        "#!/usr/bin/env python3",
        "import os, sys, time",
        f"from pathlib import Path",
        f"Path({str(pid_file)!r}).write_text(str(os.getpid()))",
        f"Path({str(marker)!r}).write_text('BKE_AGENT_READY')",
    ]
    if code:
        body.append(f"raise SystemExit({code})")
    else:
        body.append("time.sleep(60)")
    path.write_text("\n".join(body)+"\n")
    path.chmod(0o755)

def _run_agent(install:Path, artifact:Path, backup:Path, state:Path, marker:Path):
    script = """
import sys, hashlib
from pathlib import Path
from bke_updater_core.models import ProductManifest, SignedUpdatePolicy
from bke_licensing_agent.updates.orchestrator import UpdateOrchestrator
install, artifact, backup, state, marker = map(Path, sys.argv[1:6])
policy = SignedUpdatePolicy("bke.update-policy.v1","agent","1.0.0","2.0.0","1.0.0","stable","linux","x86_64","agent-release-2","agent-artifact-2",hashlib.sha256(artifact.read_bytes()).hexdigest(),artifact.stat().st_size,"application/octet-stream","2026-01-01T00:00:00Z","2026-01-01T00:00:00Z",2,"ci","Ed25519","",{})
manifest = ProductManifest("agent","1.0.0","linux","x86_64","agent",install,health_check="BKE_AGENT_READY")
UpdateOrchestrator({}, state).execute_self_update(manifest, policy, artifact, backup)
"""
    return subprocess.Popen([sys.executable,"-c",script,str(install),str(artifact),str(backup),str(state),str(marker)])

def _wait_terminal(state:Path, timeout=15):
    deadline=time.time()+timeout
    record=state/"agent-agent-release-2-2"/"state.json"
    while time.time()<deadline:
        if record.exists():
            value=json.loads(record.read_text())["state"]
            if value in {"COMMITTED","ROLLED_BACK","FAILED"}: return value
        time.sleep(.1)
    raise AssertionError("durable terminal state not reached")

def _stop_pid(pid_file:Path):
    if pid_file.exists():
        pid=int(pid_file.read_text())
        try: subprocess.run(["kill",str(pid)],check=False)
        except ValueError: pass

def test_real_broken_agent_external_helper_relaunches_restored_agent_and_reconciles(tmp_path):
    install, artifact, backup, state = tmp_path/"agent", tmp_path/"broken-agent-b", tmp_path/"backup", tmp_path/"state"
    marker, pid_file = tmp_path/"ready", tmp_path/"agent.pid"
    install.mkdir()
    executable(install/"agent",0,pid_file,marker); original=(install/"agent").read_bytes()
    executable(artifact,1,pid_file,marker)
    agent=_run_agent(install,artifact,backup,state,marker)
    try:
        assert _wait_terminal(state)=="ROLLED_BACK"
        agent.wait(timeout=5)
        assert (install/"agent").read_bytes()==original
        assert marker.read_text()=="BKE_AGENT_READY"
        restored_pid=int(pid_file.read_text())
        assert restored_pid != agent.pid
        assert Path(f"/proc/{restored_pid}").exists()
        record=json.loads((state/"agent-agent-release-2-2"/"state.json").read_text())
        assert record["state"]=="ROLLED_BACK"
    finally:
        _stop_pid(pid_file)


def test_execute_self_update_passes_configured_readiness_to_external_helper(tmp_path):
    install, artifact, backup, state = tmp_path/"agent", tmp_path/"agent-b", tmp_path/"backup", tmp_path/"state"
    install.mkdir()
    executable(install/"agent", 0, tmp_path/"a.pid", tmp_path/"a.ready")
    executable(artifact, 0, tmp_path/"b.pid", tmp_path/"b.ready")
    captured = {}
    def launcher(command, close_fds=True):
        captured["command"] = command
        return object()
    def exited(code):
        raise SystemExit(code)
    script = """
import sys
from pathlib import Path
from bke_updater_core.models import ProductManifest, SignedUpdatePolicy
from bke_licensing_agent.updates.orchestrator import UpdateOrchestrator
install, artifact, backup, state = map(Path, sys.argv[1:5])
policy = SignedUpdatePolicy("bke.update-policy.v1","agent","1.0.0","2.0.0","1.0.0","stable","linux","x86_64","release","artifact", "0"*64, artifact.stat().st_size, "application/octet-stream", "2026-01-01T00:00:00Z","2026-01-01T00:00:00Z",2,"ci","Ed25519","",{})
manifest = ProductManifest("agent","1.0.0","linux","x86_64","agent",install,health_check="BKE_AGENT_READY")
UpdateOrchestrator({}, state).execute_self_update(manifest, policy, artifact, backup)
"""
    import sys
    import subprocess
    with pytest.raises(SystemExit):
        namespace = {"__name__":"__main__"}
        # Execute through the production method with injected launcher/exit boundary.
        exec(compile("from pathlib import Path\nfrom bke_updater_core.models import ProductManifest, SignedUpdatePolicy\nfrom bke_licensing_agent.updates.orchestrator import UpdateOrchestrator\n", "<test>", "exec"), namespace)
        manifest = namespace["ProductManifest"]("agent","1.0.0","linux","x86_64","agent",install,health_check="BKE_AGENT_READY")
        policy = namespace["SignedUpdatePolicy"]("bke.update-policy.v1","agent","1.0.0","2.0.0","1.0.0","stable","linux","x86_64","release","artifact","0"*64,artifact.stat().st_size,"application/octet-stream","2026-01-01T00:00:00Z","2026-01-01T00:00:00Z",2,"ci","Ed25519","",{})
        namespace["UpdateOrchestrator"]({},state).execute_self_update(manifest,policy,artifact,backup,launch_helper=launcher,exit_process=exited)
    assert "--ready-marker" in captured["command"]
    assert captured["command"][captured["command"].index("--ready-marker")+1] == "BKE_AGENT_READY"
