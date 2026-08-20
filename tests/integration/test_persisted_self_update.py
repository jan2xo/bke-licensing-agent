import hashlib
from pathlib import Path
from bke_updater_core.models import ProductManifest, SignedUpdatePolicy, TransactionState
from bke_licensing_agent.updates.orchestrator import UpdateOrchestrator

def make_policy(artifact: Path, latest="2.0.0"):
    return SignedUpdatePolicy("bke.update-policy.v1","agent","1.0.0",latest,"1.0.0","stable","linux","x86_64","agent-release-2","agent-artifact-2",hashlib.sha256(artifact.read_bytes()).hexdigest(),artifact.stat().st_size,"application/octet-stream","2026-01-01T00:00:00Z","2026-01-01T00:00:00Z",2,"ci","Ed25519","",{})

def executable(path: Path, code: int):
    path.write_text("#!/usr/bin/env python3\nimport sys\nsys.exit(%d)\n" % code)
    path.chmod(0o755)

def test_self_update_persists_commit(tmp_path):
    install=tmp_path/"agent"; install.mkdir(); executable(install/"agent",0)
    artifact=tmp_path/"agent-b"; executable(artifact,0)
    manifest=ProductManifest("agent","1.0.0","linux","x86_64","agent",install)
    orchestrator=UpdateOrchestrator({},tmp_path/"state")
    policy=make_policy(artifact)
    result=orchestrator.execute_self_update(manifest,policy,artifact,tmp_path/"backup",health_probe=lambda _: True)
    assert result is TransactionState.COMMITTED
    record=orchestrator.read_transaction("agent-agent-release-2-2")
    assert record["state"] == "COMMITTED"

def test_self_update_persists_rollback_and_restart_can_run_agent_a(tmp_path):
    install=tmp_path/"agent"; install.mkdir(); executable(install/"agent",0)
    artifact=tmp_path/"broken-agent-b"; executable(artifact,1)
    manifest=ProductManifest("agent","1.0.0","linux","x86_64","agent",install)
    orchestrator=UpdateOrchestrator({},tmp_path/"state")
    policy=make_policy(artifact)
    result=orchestrator.execute_self_update(manifest,policy,artifact,tmp_path/"backup")
    assert result is TransactionState.ROLLED_BACK
    record=orchestrator.read_transaction("agent-agent-release-2-2")
    assert record["state"] == "ROLLED_BACK"
    assert (install/"agent").exists()
