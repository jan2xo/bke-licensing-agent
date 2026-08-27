from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bke_licensing_agent.updates.native_provisioning import (
    NativeProvisioningError,
    PrivilegedProvisioningLayout,
    provision_privileged_runtime,
)


def _payload(root: Path) -> tuple[Path, Path]:
    keys = root / "payload-keys"
    policies = root / "payload-policies"
    keys.mkdir()
    policies.mkdir()
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    (keys / "bke-target-v1.pem").write_bytes(public)
    (policies / "target.json").write_text(json.dumps({
        "schema": "bke.target-install-policy.v1",
        "product_id": "fixture-product",
        "platform": "windows",
        "architecture": "x86_64",
        "install_root": r"C:\\Program Files\\BKE Digital Solutions\\Fixture",
        "entry_point": "fixture.exe",
        "revision": 1,
        "key_id": "bke-target-v1",
        "algorithm": "Ed25519",
        "signature": "fixture-signature",
    }), encoding="utf-8")
    return keys, policies


def _layout(root: Path) -> PrivilegedProvisioningLayout:
    helper = root / "install" / "updater" / "bke-updater-core.exe"
    helper.parent.mkdir(parents=True)
    helper.write_bytes(b"helper")
    data = root / "ProgramData" / "BKE Digital Solutions" / "Licensing Agent"
    privileged = data / "privileged"
    return PrivilegedProvisioningLayout(
        data_root=data,
        runtime_root=privileged / "runtime",
        helper_executable=helper,
        signing_private_key=privileged / "agent-request-signing.pem",
        target_keys_dir=privileged / "target-keys",
        target_policies_dir=privileged / "target-policies",
        approved_install_roots=(str((root / "Program Files" / "BKE Digital Solutions").resolve()),),
    )


def test_provisioning_creates_exact_runtime_contract_and_preserves_machine_identity(tmp_path: Path):
    keys, policies = _payload(tmp_path)
    layout = _layout(tmp_path)
    protected = []

    config_path = provision_privileged_runtime(
        layout, target_keys_source=keys, target_policies_source=policies,
        protect=lambda paths: protected.extend(paths),
    )
    first_identity = layout.signing_private_key.read_bytes()
    config = json.loads(config_path.read_text())

    assert set(config) == {
        "runtime_root", "helper_executable", "signing_key_id", "signing_private_key",
        "target_keys_dir", "target_policies_dir", "approved_install_roots", "expected_channel",
    }
    assert config["helper_executable"] == str(layout.helper_executable)
    assert config["approved_install_roots"] == list(layout.approved_install_roots)
    assert config["expected_channel"] == "stable"
    assert layout.config_path in protected

    # Upgrade refreshes installer-owned trust payloads but does not rotate the
    # machine Agent request identity out from under in-flight/runtime trust.
    provision_privileged_runtime(layout, target_keys_source=keys, target_policies_source=policies)
    assert layout.signing_private_key.read_bytes() == first_identity


def test_missing_helper_fails_closed_before_writing_config(tmp_path: Path):
    keys, policies = _payload(tmp_path)
    layout = _layout(tmp_path)
    layout.helper_executable.unlink()
    with pytest.raises(NativeProvisioningError, match="helper is missing"):
        provision_privileged_runtime(layout, target_keys_source=keys, target_policies_source=policies)
    assert not layout.config_path.exists()


def test_malformed_existing_machine_identity_fails_closed_instead_of_rotating(tmp_path: Path):
    keys, policies = _payload(tmp_path)
    layout = _layout(tmp_path)
    layout.signing_private_key.parent.mkdir(parents=True, exist_ok=True)
    layout.signing_private_key.write_text("not-a-key")
    with pytest.raises(NativeProvisioningError, match="existing Agent privileged signing key is invalid"):
        provision_privileged_runtime(layout, target_keys_source=keys, target_policies_source=policies)
    assert layout.signing_private_key.read_text() == "not-a-key"


def test_empty_or_non_ed25519_target_trust_fails_closed(tmp_path: Path):
    keys, policies = _payload(tmp_path)
    layout = _layout(tmp_path)
    (keys / "bke-target-v1.pem").write_text("invalid")
    with pytest.raises(NativeProvisioningError, match="invalid BKE target public key"):
        provision_privileged_runtime(layout, target_keys_source=keys, target_policies_source=policies)
    assert not layout.config_path.exists()
