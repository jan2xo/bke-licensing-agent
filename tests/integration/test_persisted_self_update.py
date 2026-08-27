import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bke_updater_core.models import ProductManifest, SignedUpdatePolicy, TransactionState
from bke_licensing_agent.updates.orchestrator import UpdateOrchestrator
from bke_licensing_agent.updates.privileged_runtime import AgentPrivilegedRuntimeConfig


def _raw_private(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())


def _raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _runtime(tmp_path: Path) -> AgentPrivilegedRuntimeConfig:
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


def _authority(artifact: Path):
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    raw = {
        "schema": "bke.update-policy.v1", "product_id": "agent", "current_version": "1.0.0",
        "latest_version": "2.0.0", "minimum_supported_version": "1.0.0", "channel": "stable",
        "platform": "windows", "architecture": "x86_64", "release_id": "agent-release-2",
        "artifact_id": "agent-artifact-2", "artifact_sha256": digest, "artifact_size": artifact.stat().st_size,
        "artifact_content_type": "application/octet-stream", "published_at": "2026-08-27T00:00:00Z",
        "issued_at": "2026-08-27T00:00:00Z", "revision": 2, "signing_key_id": "digital-1",
        "algorithm": "Ed25519", "signature": "placeholder", "metadata": {},
    }
    policy = SignedUpdatePolicy(
        "bke.update-policy.v1", "agent", "1.0.0", "2.0.0", "1.0.0", "stable", "windows", "x86_64",
        "agent-release-2", "agent-artifact-2", digest, artifact.stat().st_size, "application/octet-stream",
        "2026-08-27T00:00:00Z", "2026-08-27T00:00:00Z", 2, "digital-1", "Ed25519", "placeholder", raw,
    )
    target = {
        "schema": "bke.install-target-policy.v1", "policy_id": "agent-windows", "revision": 3,
        "product_id": "agent", "platform": "windows", "architecture": "x86_64",
        "install_root": r"C:\Program Files\BKE Digital Solutions\BKE Licensing Agent",
        "entry_point": "BKE Licensing Agent.exe", "signing_key_id": "bke-1", "algorithm": "Ed25519",
        "signature": "placeholder",
    }
    return policy, target


def _manifest(install: Path, *, health_check: str | None = None) -> ProductManifest:
    executable = install / "agent"
    executable.write_text("agent", encoding="utf-8")
    executable.chmod(0o755)
    return ProductManifest("agent", "1.0.0", "windows", "x86_64", "agent", install, health_check=health_check)


def test_privileged_self_update_persists_durable_waiting_state_and_transaction_identity(tmp_path):
    install = tmp_path / "agent"; install.mkdir()
    artifact = tmp_path / "agent-b.exe"; artifact.write_bytes(b"new-agent")
    policy, target = _authority(artifact)
    orchestrator = UpdateOrchestrator({}, tmp_path / "state")
    captured = []

    with pytest.raises(SystemExit):
        orchestrator.execute_self_update(
            _manifest(install), policy, artifact, tmp_path / "legacy-backup",
            privileged_config=_runtime(tmp_path), target_policy=target,
            elevate=lambda command: captured.append(tuple(command)),
            exit_process=lambda code: (_ for _ in ()).throw(SystemExit(code)),
        )

    transaction_id = "agent-agent-release-2-2"
    record = orchestrator.read_transaction(transaction_id)
    assert record["state"] == TransactionState.WAITING_FOR_EXIT.value
    command = captured[0]
    assert command[command.index("--transaction-id") + 1] == transaction_id
    assert "--transaction-root" in command
    transaction_root = Path(command[command.index("--transaction-root") + 1])
    assert transaction_root.is_relative_to((tmp_path / "runtime").resolve())
    assert (tmp_path / "runtime" / "request.json").exists()
    assert (tmp_path / "runtime" / "trust.json").exists()


def test_execute_self_update_passes_configured_readiness_to_privileged_helper(tmp_path):
    install = tmp_path / "agent"; install.mkdir()
    artifact = tmp_path / "agent-b.exe"; artifact.write_bytes(b"new-agent")
    policy, target = _authority(artifact)
    captured = []

    with pytest.raises(SystemExit):
        UpdateOrchestrator({}, tmp_path / "state").execute_self_update(
            _manifest(install, health_check="BKE_AGENT_READY"), policy, artifact, tmp_path / "legacy-backup",
            privileged_config=_runtime(tmp_path), target_policy=target,
            elevate=lambda command: captured.append(tuple(command)),
            exit_process=lambda code: (_ for _ in ()).throw(SystemExit(code)),
        )

    command = captured[0]
    assert "--ready-marker" in command
    assert command[command.index("--ready-marker") + 1] == "BKE_AGENT_READY"
    assert "--install-root" not in command
    assert "--executable" not in command
