import hashlib
import sys
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bke_updater_core.helper.main import replace_and_launch
from bke_updater_core.helper.protocol import HelperPlan
from bke_updater_core.models import ProductManifest, SignedUpdatePolicy, TransactionState
from bke_licensing_agent.updates.orchestrator import UpdateOrchestrator
from bke_licensing_agent.updates.privileged_runtime import AgentPrivilegedRuntimeConfig


def executable(path: Path, marker: Path, version: str, code: int = 0):
    path.write_text(
        "#!/usr/bin/env python3\n"
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({version!r})\n"
        f"raise SystemExit({code})\n"
    )
    path.chmod(0o755)


def _raw_private(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())


def _raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _authority(artifact: Path):
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    raw = {
        "schema": "bke.update-policy.v1",
        "product_id": "agent",
        "current_version": "1.0.0",
        "latest_version": "2.0.0",
        "minimum_supported_version": "1.0.0",
        "channel": "stable",
        "platform": "windows",
        "architecture": "x86_64",
        "release_id": "agent-release-2",
        "artifact_id": "agent-artifact-2",
        "artifact_sha256": digest,
        "artifact_size": artifact.stat().st_size,
        "artifact_content_type": "application/octet-stream",
        "published_at": "2026-08-27T00:00:00Z",
        "issued_at": "2026-08-27T00:00:00Z",
        "revision": 2,
        "signing_key_id": "digital-1",
        "algorithm": "Ed25519",
        "signature": "placeholder",
        "metadata": {},
    }
    policy = SignedUpdatePolicy(
        "bke.update-policy.v1", "agent", "1.0.0", "2.0.0", "1.0.0", "stable",
        "windows", "x86_64", "agent-release-2", "agent-artifact-2", digest,
        artifact.stat().st_size, "application/octet-stream", "2026-08-27T00:00:00Z",
        "2026-08-27T00:00:00Z", 2, "digital-1", "Ed25519", "placeholder", raw,
    )
    target = {
        "schema": "bke.install-target-policy.v1",
        "policy_id": "agent-windows",
        "revision": 3,
        "product_id": "agent",
        "platform": "windows",
        "architecture": "x86_64",
        "install_root": r"C:\Program Files\BKE Digital Solutions\BKE Licensing Agent",
        "entry_point": "BKE Licensing Agent.exe",
        "signing_key_id": "bke-1",
        "algorithm": "Ed25519",
        "signature": "placeholder",
    }
    return policy, target


def _runtime(tmp_path: Path):
    helper = tmp_path / "BKE Updater Helper.exe"
    helper.write_bytes(b"helper")
    agent = Ed25519PrivateKey.generate(); digital = Ed25519PrivateKey.generate(); bke = Ed25519PrivateKey.generate()
    return AgentPrivilegedRuntimeConfig(
        runtime_root=tmp_path / "runtime",
        helper_executable=helper,
        signing_key_id="agent-local-1",
        signing_private_key=_raw_private(agent),
        trusted_digital_keys={"digital-1": _raw_public(digital)},
        trusted_bke_keys={"bke-1": _raw_public(bke)},
        approved_install_roots=(r"C:\Program Files\BKE Digital Solutions",),
        expected_channel="stable",
    )


def test_agent_a_to_b_external_helper_commit(tmp_path):
    root, stage, backup = tmp_path / "agent", tmp_path / "stage", tmp_path / "backup"
    root.mkdir(); stage.mkdir()
    executable(root / "agent", root / "started", "A")
    executable(stage / "agent", root / "started", "B")
    replace_and_launch(HelperPlan(root, stage, backup, root / "agent"))
    deadline=time.time()+5
    while time.time()<deadline and not (root/"started").exists(): time.sleep(0.05)
    assert (root / "started").read_text() == "B"


def test_broken_agent_b_restores_a_and_relaunches(tmp_path):
    root, stage, backup = tmp_path / "agent", tmp_path / "stage", tmp_path / "backup"
    root.mkdir(); stage.mkdir()
    executable(root / "agent", root / "started", "A")
    original = (root / "agent").read_bytes()
    executable(stage / "agent", root / "started", "B", code=1)
    try:
        replace_and_launch(HelperPlan(root, stage, backup, root / "agent"))
    except RuntimeError:
        pass
    else:
        raise AssertionError("broken Agent B unexpectedly committed")
    assert (root / "agent").read_bytes() == original
    import subprocess
    result = subprocess.run([str(root / "agent")], check=False)
    assert result.returncode == 0
    assert (root / "started").read_text() == "A"


def test_real_agent_process_hands_off_signed_privileged_request_before_exit(tmp_path):
    install = tmp_path / "agent"
    install.mkdir()
    executable(install / "agent", tmp_path / "started", "A")
    artifact = tmp_path / "agent-b.exe"
    artifact.write_bytes(b"new-agent")
    policy, target = _authority(artifact)
    manifest = ProductManifest("agent", "1.0.0", "windows", "x86_64", "agent", install)
    orchestrator = UpdateOrchestrator({}, tmp_path / "state")
    captured = []

    def exited(code):
        raise SystemExit(code)

    with pytest.raises(SystemExit) as exc:
        orchestrator.execute_self_update(
            manifest, policy, artifact, tmp_path / "legacy-backup",
            privileged_config=_runtime(tmp_path),
            target_policy=target,
            elevate=lambda command: captured.append(tuple(command)),
            exit_process=exited,
        )

    assert exc.value.code == 0
    assert len(captured) == 1
    command = captured[0]
    assert "--privileged-update" in command
    assert "--runtime-root" in command
    assert "--request" in command
    assert "--target-policy" in command
    assert "--install-root" not in command
    assert "--executable" not in command
    record = orchestrator.read_transaction("agent-agent-release-2-2")
    assert record["state"] == TransactionState.WAITING_FOR_EXIT.value
