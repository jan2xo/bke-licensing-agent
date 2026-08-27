import base64
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bke_updater_core.privileged import PrivilegedRequestVerifier
from bke_licensing_agent.updates.privileged_runtime import (
    AgentPrivilegedRuntimeConfig,
    PrivilegedRuntimeCompositionError,
    invoke_privileged_self_update,
    prepare_privileged_self_update,
)


def _raw_private(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())


def _raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _policy(artifact: Path) -> dict[str, object]:
    import hashlib
    payload = artifact.read_bytes()
    return {
        "schema": "bke.update-policy.v1",
        "product_id": "bke-agent",
        "current_version": "1.0.0",
        "latest_version": "2.0.0",
        "minimum_supported_version": "1.0.0",
        "channel": "stable",
        "platform": "windows",
        "architecture": "x86_64",
        "release_id": "agent-2",
        "artifact_id": "agent-2-win",
        "artifact_sha256": hashlib.sha256(payload).hexdigest(),
        "artifact_size": len(payload),
        "artifact_content_type": "application/octet-stream",
        "published_at": "2026-08-27T00:00:00Z",
        "issued_at": "2026-08-27T00:00:00Z",
        "revision": 2,
        "signing_key_id": "digital-1",
        "algorithm": "Ed25519",
        "signature": "digital-signature-placeholder",
        "metadata": {},
    }


def _target() -> dict[str, object]:
    return {
        "schema": "bke.install-target-policy.v1",
        "policy_id": "bke-agent-windows",
        "revision": 3,
        "product_id": "bke-agent",
        "platform": "windows",
        "architecture": "x86_64",
        "install_root": r"C:\Program Files\BKE Digital Solutions\BKE Licensing Agent",
        "entry_point": "BKE Licensing Agent.exe",
        "signing_key_id": "bke-1",
        "algorithm": "Ed25519",
        "signature": "bke-signature-placeholder",
    }


def _prepared(tmp_path: Path):
    runtime = tmp_path / "runtime"
    stage = runtime / "stage"
    stage.mkdir(parents=True)
    (stage / "BKE Licensing Agent.exe").write_bytes(b"new-agent")
    artifact = tmp_path / "artifact.exe"
    artifact.write_bytes(b"new-agent")
    helper = tmp_path / "BKE Updater Helper.exe"
    helper.write_bytes(b"helper")
    agent = Ed25519PrivateKey.generate()
    digital = Ed25519PrivateKey.generate()
    bke = Ed25519PrivateKey.generate()
    config = AgentPrivilegedRuntimeConfig(
        runtime_root=runtime,
        helper_executable=helper,
        signing_key_id="agent-local-1",
        signing_private_key=_raw_private(agent),
        trusted_digital_keys={"digital-1": _raw_public(digital)},
        trusted_bke_keys={"bke-1": _raw_public(bke)},
        approved_install_roots=(r"C:\Program Files\BKE Digital Solutions",),
        expected_channel="stable",
    )
    prepared = prepare_privileged_self_update(
        config,
        update_policy=_policy(artifact),
        target_policy=_target(),
        artifact=artifact,
        staged_root=stage,
        backup_root=runtime / "backup",
        transaction_id="bke-agent-agent-2-2",
        wait_pid=1234,
        now=datetime(2026, 8, 27, 7, 30, tzinfo=timezone.utc),
    )
    return prepared, agent


def test_composes_signed_one_shot_request_and_helper_owned_trust(tmp_path: Path):
    prepared, agent = _prepared(tmp_path)
    request = json.loads(prepared.request_document.read_text())
    trust = json.loads((prepared.runtime_root / "trust.json").read_text())

    verified = PrivilegedRequestVerifier(
        {"agent-local-1": _raw_public(agent)},
        consume_request_id=lambda _request_id: True,
        clock=lambda: datetime(2026, 8, 27, 7, 30, 30, tzinfo=timezone.utc),
    ).verify(request)

    assert verified.product_id == "bke-agent"
    assert verified.install_root == _target()["install_root"]
    assert trust["schema"] == "bke.updater-trust.v1"
    assert base64.b64decode(trust["agent_keys"]["agent-local-1"]) == _raw_public(agent)
    assert prepared.artifact_path.read_bytes() == b"new-agent"


def test_command_exposes_documents_not_caller_install_authority(tmp_path: Path):
    prepared, _ = _prepared(tmp_path)
    command = prepared.command

    assert "--privileged-update" in command
    assert "--runtime-root" in command
    assert "--request" in command
    assert "--update-policy" in command
    assert "--target-policy" in command
    assert "--install-root" not in command
    assert "--executable" not in command
    assert "--trusted-agent-key" not in command
    assert command[-2:] == ("--transaction-id", "bke-agent-agent-2-2")


def test_invocation_delegates_only_prepared_command(tmp_path: Path):
    prepared, _ = _prepared(tmp_path)
    calls = []

    invoke_privileged_self_update(prepared, elevate=lambda command: calls.append(tuple(command)))

    assert calls == [prepared.command]


def test_rejects_artifact_that_does_not_match_update_policy(tmp_path: Path):
    runtime = tmp_path / "runtime"
    stage = runtime / "stage"
    stage.mkdir(parents=True)
    artifact = tmp_path / "artifact.exe"
    artifact.write_bytes(b"good")
    policy = _policy(artifact)
    artifact.write_bytes(b"tampered")
    helper = tmp_path / "helper.exe"
    helper.write_bytes(b"helper")
    agent = Ed25519PrivateKey.generate()
    digital = Ed25519PrivateKey.generate()
    bke = Ed25519PrivateKey.generate()
    config = AgentPrivilegedRuntimeConfig(
        runtime_root=runtime,
        helper_executable=helper,
        signing_key_id="agent-local-1",
        signing_private_key=_raw_private(agent),
        trusted_digital_keys={"digital-1": _raw_public(digital)},
        trusted_bke_keys={"bke-1": _raw_public(bke)},
        approved_install_roots=(r"C:\Program Files\BKE Digital Solutions",),
        expected_channel="stable",
    )

    with pytest.raises(PrivilegedRuntimeCompositionError, match="artifact"):
        prepare_privileged_self_update(
            config,
            update_policy=policy,
            target_policy=_target(),
            artifact=artifact,
            staged_root=stage,
            backup_root=runtime / "backup",
            transaction_id="tx-1",
            wait_pid=1,
        )


def test_rejects_ephemeral_stage_outside_agent_runtime(tmp_path: Path):
    prepared_root = tmp_path / "runtime"
    prepared_root.mkdir()
    outside = tmp_path / "outside-stage"
    outside.mkdir()
    artifact = tmp_path / "artifact.exe"
    artifact.write_bytes(b"new-agent")
    helper = tmp_path / "helper.exe"
    helper.write_bytes(b"helper")
    agent = Ed25519PrivateKey.generate()
    digital = Ed25519PrivateKey.generate()
    bke = Ed25519PrivateKey.generate()
    config = AgentPrivilegedRuntimeConfig(
        runtime_root=prepared_root,
        helper_executable=helper,
        signing_key_id="agent-local-1",
        signing_private_key=_raw_private(agent),
        trusted_digital_keys={"digital-1": _raw_public(digital)},
        trusted_bke_keys={"bke-1": _raw_public(bke)},
        approved_install_roots=(r"C:\Program Files\BKE Digital Solutions",),
        expected_channel="stable",
    )

    with pytest.raises(PrivilegedRuntimeCompositionError, match="staged_root"):
        prepare_privileged_self_update(
            config,
            update_policy=_policy(artifact),
            target_policy=_target(),
            artifact=artifact,
            staged_root=outside,
            backup_root=prepared_root / "backup",
            transaction_id="tx-1",
            wait_pid=1,
        )
