import hashlib
from pathlib import Path
from bke_updater_core.models import ProductManifest, SignedUpdatePolicy, TransactionState
from bke_licensing_agent.updates.orchestrator import UpdateOrchestrator

def policy(artifact: Path):
    return SignedUpdatePolicy(
        schema="bke.update-policy.v1", product_id="fixture", current_version="1.0.0",
        latest_version="2.0.0", minimum_supported_version="1.0.0", channel="stable",
        platform="linux", architecture="x86_64", release_id="r2", artifact_id="a2",
        artifact_sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
        artifact_size=artifact.stat().st_size, content_type="application/octet-stream",
        published_at="2026-01-01T00:00:00Z", issued_at="2026-01-01T00:00:00Z",
        revision=2, signing_key_id="k", algorithm="Ed25519", signature="",
        raw={},
    )

def test_orchestrator_drives_real_core_replacement(tmp_path):
    install=tmp_path/"install"; install.mkdir()
    old=install/"run"; old.write_text("v1")
    artifact=tmp_path/"candidate"; artifact.write_text("v2")
    manifest=ProductManifest("fixture","1.0.0","linux","x86_64","run",install)
    result=UpdateOrchestrator({},tmp_path/"state").execute_update(
        manifest, policy(artifact), artifact, tmp_path/"backup", health_probe=lambda _: True)
    assert result is TransactionState.COMMITTED
    assert (install/"run").read_text()=="v2"
