import hashlib
import json
import stat
import zipfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bke_updater_core.models import ProductManifest, SignedUpdatePolicy, TransactionState
from bke_licensing_agent.updates.orchestrator import UPDATE_PACKAGE_CONTENT_TYPE, UpdateOrchestrator
from bke_licensing_agent.updates.privileged_runtime import AgentPrivilegedRuntimeConfig


def _raw_private(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())


def _raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _authority(artifact: Path, *, content_type: str = "application/octet-stream"):
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    raw = {
        "schema": "bke.update-policy.v1",
        "product_id": "bke-air-stack",
        "current_version": "1.0.0",
        "latest_version": "2.0.0",
        "minimum_supported_version": "1.0.0",
        "channel": "stable",
        "platform": "windows",
        "architecture": "x86_64",
        "release_id": "air-stack-2",
        "artifact_id": "air-stack-2-win",
        "artifact_sha256": digest,
        "artifact_size": artifact.stat().st_size,
        "artifact_content_type": content_type,
        "published_at": "2026-08-27T00:00:00Z",
        "issued_at": "2026-08-27T00:00:00Z",
        "revision": 2,
        "signing_key_id": "digital-1",
        "algorithm": "Ed25519",
        "signature": "placeholder",
        "metadata": {},
    }
    policy = SignedUpdatePolicy(
        "bke.update-policy.v1", "bke-air-stack", "1.0.0", "2.0.0", "1.0.0", "stable",
        "windows", "x86_64", "air-stack-2", "air-stack-2-win", digest,
        artifact.stat().st_size, content_type, "2026-08-27T00:00:00Z",
        "2026-08-27T00:00:00Z", 2, "digital-1", "Ed25519", "placeholder", raw,
    )
    target = {
        "schema": "bke.install-target-policy.v1",
        "policy_id": "air-stack-windows",
        "revision": 3,
        "product_id": "bke-air-stack",
        "platform": "windows",
        "architecture": "x86_64",
        "install_root": r"C:\Program Files\BKE Digital Solutions\Air Stack",
        "entry_point": "Air Stack.exe",
        "signing_key_id": "bke-1",
        "algorithm": "Ed25519",
        "signature": "placeholder",
    }
    return policy, target


def _runtime(tmp_path: Path) -> AgentPrivilegedRuntimeConfig:
    helper = tmp_path / "BKE Updater Helper.exe"
    helper.write_bytes(b"helper")
    agent = Ed25519PrivateKey.generate()
    digital = Ed25519PrivateKey.generate()
    bke = Ed25519PrivateKey.generate()
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


def _manifest(install: Path) -> ProductManifest:
    return ProductManifest(
        "bke-air-stack", "1.0.0", "windows", "x86_64", "Air Stack.exe", install,
        health_check="BKE_AIR_STACK_READY",
    )


def test_product_update_hands_off_signed_privileged_command_without_agent_exit(tmp_path: Path):
    install = tmp_path / "air-stack"
    install.mkdir()
    (install / "Air Stack.exe").write_bytes(b"old")
    artifact = tmp_path / "AirStackSetup.exe"
    artifact.write_bytes(b"new")
    policy, target = _authority(artifact)
    manifest = _manifest(install)
    orchestrator = UpdateOrchestrator({}, tmp_path / "state")
    captured = []

    result = orchestrator.execute_privileged_update(
        manifest,
        policy,
        artifact,
        privileged_config=_runtime(tmp_path),
        target_policy=target,
        elevate=lambda command: captured.append(tuple(command)),
    )

    assert result is TransactionState.STAGED
    assert len(captured) == 1
    command = captured[0]
    assert "--privileged-update" in command
    assert "--runtime-root" in command
    assert "--request" in command
    assert "--update-policy" in command
    assert "--target-policy" in command
    assert "--artifact" in command
    assert "--wait-pid" not in command
    assert command[command.index("--ready-marker") + 1] == "BKE_AIR_STACK_READY"
    assert "--install-root" not in command
    assert "--executable" not in command

    transaction = json.loads((tmp_path / "state" / "bke-air-stack-air-stack-2-2" / "state.json").read_text())
    assert transaction["state"] == "STAGED"
    assert transaction["privileged"] is True


def test_updater_package_extracts_full_tree_before_privileged_handoff(tmp_path: Path):
    install = tmp_path / "air-stack"
    install.mkdir()
    (install / "Air Stack.exe").write_bytes(b"old")
    artifact = tmp_path / "AirStack.update.zip"
    with zipfile.ZipFile(artifact, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("Air Stack.exe", b"new-executable")
        archive.writestr("assets/config.json", b'{"version":"2.0.0"}')
        archive.writestr("runtime/dependency.dll", b"dependency")
    policy, target = _authority(artifact, content_type=UPDATE_PACKAGE_CONTENT_TYPE)
    orchestrator = UpdateOrchestrator({}, tmp_path / "state")

    result = orchestrator.execute_privileged_update(
        _manifest(install), policy, artifact,
        privileged_config=_runtime(tmp_path), target_policy=target,
        elevate=lambda _command: None,
    )

    assert result is TransactionState.STAGED
    stage = tmp_path / "runtime" / "stage" / "bke-air-stack-air-stack-2-2"
    assert (stage / "Air Stack.exe").read_bytes() == b"new-executable"
    assert (stage / "assets" / "config.json").read_bytes() == b'{"version":"2.0.0"}'
    assert (stage / "runtime" / "dependency.dll").read_bytes() == b"dependency"
    assert (stage / "Air Stack.exe").read_bytes() != artifact.read_bytes()


def test_updater_package_rejects_path_traversal(tmp_path: Path):
    install = tmp_path / "air-stack"
    install.mkdir()
    (install / "Air Stack.exe").write_bytes(b"old")
    artifact = tmp_path / "traversal.update.zip"
    with zipfile.ZipFile(artifact, "w") as archive:
        archive.writestr("Air Stack.exe", b"new")
        archive.writestr("../escaped.txt", b"escape")
    policy, target = _authority(artifact, content_type=UPDATE_PACKAGE_CONTENT_TYPE)

    with pytest.raises(ValueError, match="unsafe updater package path"):
        UpdateOrchestrator({}, tmp_path / "state").execute_privileged_update(
            _manifest(install), policy, artifact,
            privileged_config=_runtime(tmp_path), target_policy=target,
            elevate=lambda _command: None,
        )

    assert not (tmp_path / "runtime" / "stage" / "escaped.txt").exists()


def test_updater_package_rejects_symlinks(tmp_path: Path):
    install = tmp_path / "air-stack"
    install.mkdir()
    (install / "Air Stack.exe").write_bytes(b"old")
    artifact = tmp_path / "symlink.update.zip"
    with zipfile.ZipFile(artifact, "w") as archive:
        archive.writestr("Air Stack.exe", b"new")
        link = zipfile.ZipInfo("runtime-link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(link, "Air Stack.exe")
    policy, target = _authority(artifact, content_type=UPDATE_PACKAGE_CONTENT_TYPE)

    with pytest.raises(ValueError, match="symlinks are forbidden"):
        UpdateOrchestrator({}, tmp_path / "state").execute_privileged_update(
            _manifest(install), policy, artifact,
            privileged_config=_runtime(tmp_path), target_policy=target,
            elevate=lambda _command: None,
        )


def test_product_update_rejects_manifest_that_does_not_match_signed_update_policy(tmp_path: Path):
    install = tmp_path / "air-stack"
    install.mkdir()
    (install / "Air Stack.exe").write_bytes(b"old")
    artifact = tmp_path / "AirStackSetup.exe"
    artifact.write_bytes(b"new")
    policy, target = _authority(artifact)
    manifest = ProductManifest("bke-render-dock", "1.0.0", "windows", "x86_64", "Air Stack.exe", install)

    with pytest.raises(ValueError, match="signed update policy"):
        UpdateOrchestrator({}, tmp_path / "state").execute_privileged_update(
            manifest,
            policy,
            artifact,
            privileged_config=_runtime(tmp_path),
            target_policy=target,
            elevate=lambda _command: None,
        )


def test_product_update_requires_agent_owned_runtime_and_signed_target_policy(tmp_path: Path):
    install = tmp_path / "air-stack"
    install.mkdir()
    (install / "Air Stack.exe").write_bytes(b"old")
    artifact = tmp_path / "AirStackSetup.exe"
    artifact.write_bytes(b"new")
    policy, _target = _authority(artifact)
    manifest = ProductManifest("bke-air-stack", "1.0.0", "windows", "x86_64", "Air Stack.exe", install)

    with pytest.raises(ValueError, match="runtime config"):
        UpdateOrchestrator({}, tmp_path / "state").execute_privileged_update(manifest, policy, artifact)
