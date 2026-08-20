import hashlib, json, subprocess, sys, time
from pathlib import Path

def executable(path:Path, code:int):
    path.write_text("#!/usr/bin/env python3\nimport sys\nsys.exit(%d)\n"%code); path.chmod(0o755)

def _run_agent(install:Path, artifact:Path, backup:Path, state:Path, code:int):
    script = """
import sys
from pathlib import Path
from bke_updater_core.models import ProductManifest, SignedUpdatePolicy
from bke_licensing_agent.updates.orchestrator import UpdateOrchestrator
install, artifact, backup, state = map(Path, sys.argv[1:5])
policy = SignedUpdatePolicy("bke.update-policy.v1","agent","1.0.0","2.0.0","1.0.0","stable","linux","x86_64","agent-release-2","agent-artifact-2",__import__("hashlib").sha256(artifact.read_bytes()).hexdigest(),artifact.stat().st_size,"application/octet-stream","2026-01-01T00:00:00Z","2026-01-01T00:00:00Z",2,"ci","Ed25519","",{})
manifest = ProductManifest("agent","1.0.0","linux","x86_64","agent",install)
UpdateOrchestrator({}, state).execute_self_update(manifest, policy, artifact, backup)
"""
    return subprocess.Popen([sys.executable,"-c",script,str(install),str(artifact),str(backup),str(state)])

def _wait_terminal(state:Path, timeout=10):
    deadline=time.time()+timeout
    while time.time()<deadline:
        record=state/"agent-agent-release-2-2"/"state.json"
        if record.exists():
            value=json.loads(record.read_text())["state"]
            if value in {"COMMITTED","ROLLED_BACK","FAILED"}: return value
        time.sleep(.1)
    raise AssertionError("durable terminal state not reached")

def test_real_broken_agent_external_helper_rolls_back_and_reconciles_after_restart(tmp_path):
    install, stage_artifact, backup, state = tmp_path/"agent", tmp_path/"broken-agent-b", tmp_path/"backup", tmp_path/"state"
    install.mkdir()
    executable(install/"agent",0); original=(install/"agent").read_bytes()
    executable(stage_artifact,1)
    agent=_run_agent(install,stage_artifact,backup,state,1)
    assert _wait_terminal(state)=="ROLLED_BACK"
    agent.wait(timeout=5)
    assert (install/"agent").read_bytes()==original
    restored=subprocess.run([str(install/"agent")],check=False)
    assert restored.returncode==0
    restarted=json.loads((state/"agent-agent-release-2-2"/"state.json").read_text())
    assert restarted["state"]=="ROLLED_BACK"
