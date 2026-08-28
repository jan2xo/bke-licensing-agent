"""Fail-closed installed product privileged update composition."""
from __future__ import annotations

import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from bke_updater_core.models import Decision, ProductManifest, TransactionState
from bke_updater_core.target_policy import TargetInstallPolicyVerifier

from ..api.models import UpdateDiscoveryRequest
from .acquisition import acquire_artifact
from .discovery import UPDATE_PACKAGE_CONTENT_TYPE, raw_update_keys
from .orchestrator import UpdateOrchestrator
from .privileged_runtime import AgentPrivilegedRuntimeConfig


class InstalledPrivilegedUpdateError(ValueError):
    pass


def _raw_public_keys(directory: Path) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    for path in sorted(directory.glob("*.pem")):
        loaded = serialization.load_pem_public_key(path.read_bytes())
        if isinstance(loaded, Ed25519PublicKey):
            result[path.stem] = loaded.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return result


def _raw_private_key(path: Path) -> bytes:
    loaded = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(loaded, Ed25519PrivateKey):
        raise InstalledPrivilegedUpdateError("Agent privileged signing key must be Ed25519")
    return loaded.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())


def load_installed_privileged_config(data_root: Path) -> tuple[AgentPrivilegedRuntimeConfig, Path]:
    """Load machine-installed privilege authority from Agent-owned configuration.

    No product identity or install target is inferred from caller input. The installer
    provisions this document and its key/policy directories into protected Agent data.
    """
    path = Path(os.getenv("BKE_PRIVILEGED_CONFIG", data_root / "privileged-update.json"))
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise InstalledPrivilegedUpdateError("privileged runtime configuration unavailable") from exc
    required = {"runtime_root", "helper_executable", "signing_key_id", "signing_private_key",
                "target_keys_dir", "target_policies_dir", "approved_install_roots", "expected_channel"}
    if set(document) != required:
        raise InstalledPrivilegedUpdateError("invalid privileged runtime configuration")
    roots = document["approved_install_roots"]
    if not isinstance(roots, list) or not roots or not all(isinstance(item, str) and item for item in roots):
        raise InstalledPrivilegedUpdateError("approved install roots are required")
    target_keys_dir = Path(document["target_keys_dir"])
    target_keys = _raw_public_keys(target_keys_dir)
    if not target_keys:
        raise InstalledPrivilegedUpdateError("trusted BKE target keys unavailable")
    config = AgentPrivilegedRuntimeConfig(
        runtime_root=Path(document["runtime_root"]),
        helper_executable=Path(document["helper_executable"]),
        signing_key_id=str(document["signing_key_id"]),
        signing_private_key=_raw_private_key(Path(document["signing_private_key"])),
        trusted_digital_keys={},
        trusted_bke_keys=target_keys,
        approved_install_roots=tuple(roots),
        expected_channel=str(document["expected_channel"]),
    )
    return config, Path(document["target_policies_dir"])


def resolve_signed_target_policy(product_id: str, platform: str, architecture: str,
                                 config: AgentPrivilegedRuntimeConfig, policy_dir: Path) -> dict[str, object]:
    verifier = TargetInstallPolicyVerifier(dict(config.trusted_bke_keys), approved_roots=config.approved_install_roots)
    matches = []
    for path in sorted(policy_dir.glob("*.json")):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
            verified = verifier.verify(document)
        except Exception:
            continue
        if (verified.product_id == product_id and verified.platform == platform and
                verified.architecture == architecture):
            matches.append(verified)
    if not matches:
        raise InstalledPrivilegedUpdateError("no verified BKE install-target policy")
    selected = max(matches, key=lambda item: item.revision)
    return selected.raw


def execute_installed_product_update(runtime, product_id: str, version: str) -> TransactionState:
    """Re-authorize, reacquire, and hand one installed product update to the helper."""
    resolved = runtime._validated_product_record(product_id, version)
    lease = runtime._update_lease(product_id, version)
    if resolved is None or lease is None:
        raise InstalledPrivilegedUpdateError("product or entitlement unavailable")
    record, manifest = resolved
    envelope = {"payload": lease.signed_payload, "signature": lease.signed_signature,
                "key_id": lease.key_id, "algorithm": lease.signed_algorithm}
    response = runtime.update_discovery.client.check_update(UpdateDiscoveryRequest(
        lease=envelope, product_id=product_id, current_version=version,
        platform=manifest.platform, architecture=manifest.architecture, channel=manifest.updateChannel,
    ))
    if response.status != "update_available" or response.policy is None or response.download_url is None:
        raise InstalledPrivilegedUpdateError("authority no longer offers this update")

    core_manifest = ProductManifest(
        manifest.productId, manifest.version, manifest.platform, manifest.architecture,
        manifest.entryPoint, Path(record.product_root), update_channel=manifest.updateChannel,
    )
    trusted_digital = raw_update_keys(runtime.update_discovery.trusted_keys())
    orchestrator = UpdateOrchestrator(trusted_digital, runtime.update_discovery.state_root / "core")
    verified = orchestrator.verify_policy(response.policy, core_manifest)
    if verified.content_type != UPDATE_PACKAGE_CONTENT_TYPE:
        raise InstalledPrivilegedUpdateError("signed policy does not authorize a BKE updater package")
    if orchestrator.decide(core_manifest, verified) not in {Decision.UPDATE_AVAILABLE, Decision.UPDATE_REQUIRED}:
        raise InstalledPrivilegedUpdateError("signed policy no longer authorizes an update")

    config, target_policy_dir = load_installed_privileged_config(runtime.database.path.parent)
    if config.expected_channel != manifest.updateChannel:
        raise InstalledPrivilegedUpdateError("privileged runtime channel mismatch")
    config = AgentPrivilegedRuntimeConfig(
        runtime_root=config.runtime_root,
        helper_executable=config.helper_executable,
        signing_key_id=config.signing_key_id,
        signing_private_key=config.signing_private_key,
        trusted_digital_keys=trusted_digital,
        trusted_bke_keys=config.trusted_bke_keys,
        approved_install_roots=config.approved_install_roots,
        expected_channel=config.expected_channel,
        request_lifetime_seconds=config.request_lifetime_seconds,
    )
    target_policy = resolve_signed_target_policy(product_id, manifest.platform, manifest.architecture,
                                                 config, target_policy_dir)
    destination = config.runtime_root / "downloads" / f"{verified.artifact_id}.bin"
    artifact = acquire_artifact(response.download_url, destination,
                                expected_size=verified.artifact_size,
                                expected_sha256=verified.artifact_sha256)
    return orchestrator.execute_privileged_update(
        core_manifest, verified, artifact,
        privileged_config=config, target_policy=target_policy,
    )
