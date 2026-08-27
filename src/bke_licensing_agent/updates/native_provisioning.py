"""Installer-owned provisioning for the privileged update runtime.

This module creates machine trust state consumed by ``installed_privileged``.
Products and loopback callers never invoke it; native installers run it while
holding the OS privilege needed to protect the resulting directories.
"""
from __future__ import annotations

import base64
import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class NativeProvisioningError(ValueError):
    pass


@dataclass(frozen=True)
class PrivilegedProvisioningLayout:
    data_root: Path
    runtime_root: Path
    helper_executable: Path
    signing_private_key: Path
    target_keys_dir: Path
    target_policies_dir: Path
    approved_install_roots: tuple[str, ...]
    expected_channel: str = "stable"
    signing_key_id: str = "agent-machine-ed25519-v1"

    @property
    def config_path(self) -> Path:
        return self.data_root / "privileged-update.json"


def _validate_public_keys(directory: Path) -> dict[str, Ed25519PublicKey]:
    paths = sorted(directory.glob("*.pem"))
    if not paths:
        raise NativeProvisioningError("at least one BKE target public key is required")
    keys: dict[str, Ed25519PublicKey] = {}
    for path in paths:
        try:
            key = serialization.load_pem_public_key(path.read_bytes())
        except Exception as exc:
            raise NativeProvisioningError(f"invalid BKE target public key: {path.name}") from exc
        if not isinstance(key, Ed25519PublicKey):
            raise NativeProvisioningError(f"BKE target key must be Ed25519: {path.name}")
        keys[path.stem] = key
    return keys


def _validate_policies(directory: Path, keys: dict[str, Ed25519PublicKey]) -> None:
    paths = sorted(directory.glob("*.json"))
    if not paths:
        raise NativeProvisioningError("at least one signed BKE target policy is required")
    required = {
        "schema", "policy_id", "revision", "product_id", "platform", "architecture",
        "install_root", "entry_point", "signing_key_id", "algorithm", "signature",
    }
    for path in paths:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise NativeProvisioningError(f"invalid target policy document: {path.name}") from exc
        if set(document) != required:
            raise NativeProvisioningError(f"unsupported target policy contract: {path.name}")
        if document.get("schema") != "bke.install-target-policy.v1" or document.get("algorithm") != "Ed25519":
            raise NativeProvisioningError(f"unsupported target policy contract: {path.name}")
        key_id = document.get("signing_key_id")
        key = keys.get(key_id) if isinstance(key_id, str) else None
        if key is None:
            raise NativeProvisioningError(f"unknown BKE target signing key: {path.name}")
        signature = document.get("signature")
        if not isinstance(signature, str):
            raise NativeProvisioningError(f"invalid target policy signature: {path.name}")
        unsigned = {name: value for name, value in document.items() if name != "signature"}
        canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        try:
            key.verify(base64.b64decode(signature, validate=True), canonical)
        except Exception as exc:
            raise NativeProvisioningError(f"invalid target policy signature: {path.name}") from exc


def _ensure_machine_signing_key(path: Path) -> None:
    if path.exists():
        try:
            key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        except Exception as exc:
            raise NativeProvisioningError("existing Agent privileged signing key is invalid") from exc
        if not isinstance(key, Ed25519PrivateKey):
            raise NativeProvisioningError("existing Agent privileged signing key must be Ed25519")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    encoded = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    if os.name != "nt":
        path.chmod(0o600)


def _replace_directory(source: Path, destination: Path, *, suffix: str) -> None:
    if not source.is_dir():
        raise NativeProvisioningError(f"provisioning source unavailable: {source}")
    staging = destination.with_name(destination.name + suffix)
    if staging.exists():
        shutil.rmtree(staging)
    shutil.copytree(source, staging)
    previous = destination.with_name(destination.name + ".previous")
    if previous.exists():
        shutil.rmtree(previous)
    if destination.exists():
        os.replace(destination, previous)
    os.replace(staging, destination)
    if previous.exists():
        shutil.rmtree(previous)


def _write_config(layout: PrivilegedProvisioningLayout) -> None:
    document = {
        "runtime_root": str(layout.runtime_root),
        "helper_executable": str(layout.helper_executable),
        "signing_key_id": layout.signing_key_id,
        "signing_private_key": str(layout.signing_private_key),
        "target_keys_dir": str(layout.target_keys_dir),
        "target_policies_dir": str(layout.target_policies_dir),
        "approved_install_roots": list(layout.approved_install_roots),
        "expected_channel": layout.expected_channel,
    }
    temporary = layout.config_path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, layout.config_path)
    if os.name != "nt":
        layout.config_path.chmod(0o600)


def provision_privileged_runtime(
    layout: PrivilegedProvisioningLayout,
    *,
    target_keys_source: Path,
    target_policies_source: Path,
    protect: Callable[[Iterable[Path]], None] | None = None,
) -> Path:
    """Provision or upgrade machine trust state while preserving Agent identity.

    Trust/key/policy sources are installer payloads. The existing machine signing
    key is deliberately retained across upgrades; malformed existing identity
    fails closed instead of silently rotating it.
    """
    if not layout.helper_executable.is_file():
        raise NativeProvisioningError("trusted Updater Core helper is missing")
    if not layout.approved_install_roots or not all(Path(root).is_absolute() for root in layout.approved_install_roots):
        raise NativeProvisioningError("approved installation roots must be absolute")
    if layout.expected_channel not in {"stable", "beta"}:
        raise NativeProvisioningError("unsupported privileged update channel")

    keys = _validate_public_keys(target_keys_source)
    _validate_policies(target_policies_source, keys)
    layout.data_root.mkdir(parents=True, exist_ok=True)
    layout.runtime_root.mkdir(parents=True, exist_ok=True)
    _ensure_machine_signing_key(layout.signing_private_key)
    _replace_directory(target_keys_source, layout.target_keys_dir, suffix=".staging")
    _replace_directory(target_policies_source, layout.target_policies_dir, suffix=".staging")
    _write_config(layout)

    protected = (
        layout.data_root,
        layout.runtime_root,
        layout.signing_private_key,
        layout.target_keys_dir,
        layout.target_policies_dir,
        layout.config_path,
    )
    if protect is not None:
        protect(protected)
    return layout.config_path
