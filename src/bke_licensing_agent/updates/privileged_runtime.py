"""Agent-owned composition for the Updater Core privileged update boundary."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Mapping, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bke_updater_core.windows_elevation import (
    PrivilegedInvocationFiles,
    build_elevated_command,
    request_windows_elevation,
)


class PrivilegedRuntimeCompositionError(ValueError):
    """Raised when the Agent cannot safely compose a privileged invocation."""


def _canonical(document: Mapping[str, object]) -> bytes:
    return json.dumps(dict(document), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _document_sha256(document: Mapping[str, object]) -> str:
    return hashlib.sha256(_canonical(document)).hexdigest()


def _write_private_json(path: Path, document: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dict(document), sort_keys=True, separators=(",", ":")), encoding="utf-8")
    if os.name != "nt":
        path.chmod(0o600)


def _under(root: Path, value: Path, field: str, *, must_exist: bool) -> Path:
    resolved_root = root.resolve()
    resolved = value.resolve(strict=must_exist)
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise PrivilegedRuntimeCompositionError(f"{field} must be inside the Agent-owned runtime root") from exc
    return resolved


@dataclass(frozen=True)
class AgentPrivilegedRuntimeConfig:
    runtime_root: Path
    helper_executable: Path
    signing_key_id: str
    signing_private_key: bytes
    trusted_digital_keys: Mapping[str, bytes]
    trusted_bke_keys: Mapping[str, bytes]
    approved_install_roots: tuple[str, ...]
    expected_channel: str
    request_lifetime_seconds: int = 120

    def private_key(self) -> Ed25519PrivateKey:
        if len(self.signing_private_key) != 32:
            raise PrivilegedRuntimeCompositionError("Agent Ed25519 private key must be 32 raw bytes")
        return Ed25519PrivateKey.from_private_bytes(self.signing_private_key)


@dataclass(frozen=True)
class PreparedPrivilegedInvocation:
    runtime_root: Path
    request_document: Path
    update_policy_document: Path
    target_policy_document: Path
    artifact_path: Path
    staged_root: Path
    backup_root: Path
    transaction_root: Path
    command: tuple[str, ...]


def _encoded_keys(keys: Mapping[str, bytes], field: str) -> dict[str, str]:
    if not keys:
        raise PrivilegedRuntimeCompositionError(f"{field} cannot be empty")
    encoded: dict[str, str] = {}
    for key_id, raw in keys.items():
        if not isinstance(key_id, str) or not key_id or not isinstance(raw, bytes) or len(raw) != 32:
            raise PrivilegedRuntimeCompositionError(f"invalid {field}")
        encoded[key_id] = base64.b64encode(raw).decode("ascii")
    return encoded


def prepare_privileged_update(
    config: AgentPrivilegedRuntimeConfig,
    *,
    update_policy: Mapping[str, object],
    target_policy: Mapping[str, object],
    artifact: Path,
    staged_root: Path,
    backup_root: Path,
    transaction_id: str,
    wait_pid: int | None = None,
    now: datetime | None = None,
) -> PreparedPrivilegedInvocation:
    """Persist trusted runtime inputs and sign one bounded privileged update request.

    Product identity, versions, platform, architecture, install root and entry point
    are derived from signed authority documents. The optional wait PID is helper
    lifecycle coordination only; it is never update authority.
    """
    if not transaction_id:
        raise PrivilegedRuntimeCompositionError("transaction_id is required")
    if wait_pid is not None and wait_pid <= 0:
        raise PrivilegedRuntimeCompositionError("wait_pid must be positive")
    if not 1 <= config.request_lifetime_seconds <= 300:
        raise PrivilegedRuntimeCompositionError("request lifetime must be between 1 and 300 seconds")

    root = config.runtime_root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        root.chmod(0o700)

    helper = config.helper_executable.resolve(strict=True)
    stage = _under(root, staged_root, "staged_root", must_exist=True)
    backup = _under(root, backup_root, "backup_root", must_exist=False)
    transaction_root = _under(root, root / "transactions", "transaction_root", must_exist=False)
    transaction_root.mkdir(parents=True, exist_ok=True)

    artifact_source = artifact.resolve(strict=True)
    artifact_bytes = artifact_source.read_bytes()
    artifact_sha256 = hashlib.sha256(artifact_bytes).hexdigest()
    artifact_size = len(artifact_bytes)
    if update_policy.get("artifact_sha256") != artifact_sha256 or update_policy.get("artifact_size") != artifact_size:
        raise PrivilegedRuntimeCompositionError("artifact does not match the signed update policy")

    bindings = (
        ("product_id", update_policy.get("product_id"), target_policy.get("product_id")),
        ("platform", update_policy.get("platform"), target_policy.get("platform")),
        ("architecture", update_policy.get("architecture"), target_policy.get("architecture")),
    )
    for field, left, right in bindings:
        if not isinstance(left, str) or not left or left != right:
            raise PrivilegedRuntimeCompositionError(f"{field} authority mismatch")

    current_version = update_policy.get("current_version")
    target_version = update_policy.get("latest_version")
    install_root = target_policy.get("install_root")
    entry_point = target_policy.get("entry_point")
    for field, value in (
        ("current_version", current_version),
        ("latest_version", target_version),
        ("install_root", install_root),
        ("entry_point", entry_point),
    ):
        if not isinstance(value, str) or not value:
            raise PrivilegedRuntimeCompositionError(f"invalid {field}")

    private_key = config.private_key()
    public_key = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if not config.signing_key_id:
        raise PrivilegedRuntimeCompositionError("Agent signing key id is required")
    if not config.approved_install_roots or not config.expected_channel:
        raise PrivilegedRuntimeCompositionError("trusted runtime policy is incomplete")

    trust = {
        "schema": "bke.updater-trust.v1",
        "agent_keys": {config.signing_key_id: base64.b64encode(public_key).decode("ascii")},
        "digital_keys": _encoded_keys(config.trusted_digital_keys, "trusted_digital_keys"),
        "target_keys": _encoded_keys(config.trusted_bke_keys, "trusted_bke_keys"),
        "approved_install_roots": list(config.approved_install_roots),
        "expected_channel": config.expected_channel,
    }
    _write_private_json(root / "trust.json", trust)

    update_path = root / "update-policy.json"
    target_path = root / "target-policy.json"
    _write_private_json(update_path, update_policy)
    _write_private_json(target_path, target_policy)

    artifact_path = root / "artifact.bin"
    artifact_path.write_bytes(artifact_bytes)
    if os.name != "nt":
        artifact_path.chmod(0o600)

    issued = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    expires = issued + timedelta(seconds=config.request_lifetime_seconds)
    unsigned: dict[str, object] = {
        "schema": "bke.privileged-update-request.v1",
        "request_id": f"agent-{uuid.uuid4().hex}",
        "product_id": update_policy["product_id"],
        "current_version": current_version,
        "target_version": target_version,
        "platform": update_policy["platform"],
        "architecture": update_policy["architecture"],
        "install_root": install_root,
        "entry_point": entry_point,
        "artifact_sha256": artifact_sha256,
        "artifact_size": artifact_size,
        "update_policy_sha256": _document_sha256(update_policy),
        "target_policy_sha256": _document_sha256(target_policy),
        "issued_at": issued.isoformat().replace("+00:00", "Z"),
        "expires_at": expires.isoformat().replace("+00:00", "Z"),
        "signing_key_id": config.signing_key_id,
        "algorithm": "Ed25519",
    }
    request_document = dict(unsigned)
    request_document["signature"] = base64.b64encode(private_key.sign(_canonical(unsigned))).decode("ascii")
    request_path = root / "request.json"
    _write_private_json(request_path, request_document)

    files = PrivilegedInvocationFiles(
        runtime_root=root,
        request_document=request_path,
        update_policy_document=update_path,
        target_policy_document=target_path,
        artifact_path=artifact_path,
        staged_root=stage,
        backup_root=backup,
        transaction_root=transaction_root,
    )
    command = build_elevated_command(helper, files, wait_pid=wait_pid)
    command = (*command, "--transaction-id", transaction_id)
    return PreparedPrivilegedInvocation(
        runtime_root=root,
        request_document=request_path,
        update_policy_document=update_path,
        target_policy_document=target_path,
        artifact_path=artifact_path,
        staged_root=stage,
        backup_root=backup,
        transaction_root=transaction_root,
        command=command,
    )


def prepare_privileged_self_update(
    config: AgentPrivilegedRuntimeConfig,
    *,
    update_policy: Mapping[str, object],
    target_policy: Mapping[str, object],
    artifact: Path,
    staged_root: Path,
    backup_root: Path,
    transaction_id: str,
    wait_pid: int,
    now: datetime | None = None,
) -> PreparedPrivilegedInvocation:
    """Compose a privileged update that waits for the Agent process to exit."""
    return prepare_privileged_update(
        config,
        update_policy=update_policy,
        target_policy=target_policy,
        artifact=artifact,
        staged_root=staged_root,
        backup_root=backup_root,
        transaction_id=transaction_id,
        wait_pid=wait_pid,
        now=now,
    )


def invoke_privileged_self_update(
    prepared: PreparedPrivilegedInvocation,
    *,
    elevate: Callable[[Sequence[str]], None] = request_windows_elevation,
) -> None:
    """Request elevation only after Agent-owned signed runtime composition."""
    elevate(prepared.command)
