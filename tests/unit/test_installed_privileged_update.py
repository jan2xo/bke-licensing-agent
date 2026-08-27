import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bke_licensing_agent.updates.installed_privileged import (
    InstalledPrivilegedUpdateError,
    load_installed_privileged_config,
    resolve_signed_target_policy,
)


def _private_pem(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def _public_pem(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def _signed_target(key: Ed25519PrivateKey, *, revision: int = 1) -> dict[str, object]:
    document: dict[str, object] = {
        "schema": "bke.install-target-policy.v1", "policy_id": "bke-demo-windows",
        "revision": revision, "product_id": "bke-demo", "platform": "windows",
        "architecture": "x86_64", "install_root": r"C:\Program Files\BKE Digital Solutions\Demo",
        "entry_point": "Demo.exe", "signing_key_id": "bke-target-1", "algorithm": "Ed25519",
    }
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    document["signature"] = base64.b64encode(key.sign(canonical)).decode("ascii")
    return document


def _configuration(tmp_path: Path):
    agent = Ed25519PrivateKey.generate()
    target = Ed25519PrivateKey.generate()
    helper = tmp_path / "helper.exe"; helper.write_bytes(b"helper")
    private = tmp_path / "agent.pem"; private.write_bytes(_private_pem(agent))
    keys = tmp_path / "target-keys"; keys.mkdir(); (keys / "bke-target-1.pem").write_bytes(_public_pem(target))
    policies = tmp_path / "target-policies"; policies.mkdir()
    runtime = tmp_path / "runtime"
    config = {
        "runtime_root": str(runtime), "helper_executable": str(helper),
        "signing_key_id": "agent-local-1", "signing_private_key": str(private),
        "target_keys_dir": str(keys), "target_policies_dir": str(policies),
        "approved_install_roots": [r"C:\Program Files\BKE Digital Solutions"],
        "expected_channel": "stable",
    }
    (tmp_path / "privileged-update.json").write_text(json.dumps(config))
    return target, policies


def test_loads_installer_provisioned_privileged_runtime_and_resolves_signed_target(tmp_path: Path):
    target, policies = _configuration(tmp_path)
    (policies / "demo.json").write_text(json.dumps(_signed_target(target)))
    config, policy_dir = load_installed_privileged_config(tmp_path)
    resolved = resolve_signed_target_policy("bke-demo", "windows", "x86_64", config, policy_dir)
    assert config.signing_key_id == "agent-local-1"
    assert config.expected_channel == "stable"
    assert resolved["install_root"] == r"C:\Program Files\BKE Digital Solutions\Demo"


def test_target_resolution_ignores_tampered_policy_and_fails_closed(tmp_path: Path):
    target, policies = _configuration(tmp_path)
    document = _signed_target(target)
    document["install_root"] = r"C:\Windows\System32"
    (policies / "tampered.json").write_text(json.dumps(document))
    config, policy_dir = load_installed_privileged_config(tmp_path)
    with pytest.raises(InstalledPrivilegedUpdateError, match="no verified"):
        resolve_signed_target_policy("bke-demo", "windows", "x86_64", config, policy_dir)


def test_missing_installed_privileged_configuration_fails_closed(tmp_path: Path):
    with pytest.raises(InstalledPrivilegedUpdateError, match="configuration unavailable"):
        load_installed_privileged_config(tmp_path)
