"""Agent-owned preparation of signed staged-tree update packages.

This module deliberately stops before privileged replacement. It acquires the
short-lived Digital grant, verifies exact signed bytes, and expands the package
through bke-updater-core's safe staging contract. Product applications never
receive the grant URL or resulting filesystem paths.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from bke_updater_core import stage_verified_zip
from bke_updater_core.models import ProductManifest, SignedUpdatePolicy

from .acquisition import acquire_artifact

UPDATE_PACKAGE_CONTENT_TYPE = "application/vnd.bke.update-package+zip"


@dataclass(frozen=True)
class PreparedUpdate:
    transaction_id: str
    artifact_path: Path
    staged_root: Path


def prepare_staged_update(*, manifest: ProductManifest, policy: SignedUpdatePolicy,
                          download_url: str, state_root: Path,
                          allow_loopback_http: bool = False) -> PreparedUpdate:
    """Download, verify, and safely expand one signed BKE updater package."""
    if policy.content_type != UPDATE_PACKAGE_CONTENT_TYPE:
        raise ValueError("update policy does not authorize a staged-tree package")
    safe_product = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in manifest.product_id)[:96]
    safe_release = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in policy.release_id)[:96]
    transaction_id = f"{safe_product}-{safe_release}-{policy.revision}"[:220]
    root = state_root / "prepared" / transaction_id
    artifact_path = root / "artifact.update.zip"
    staged_root = root / "staged"
    root.mkdir(parents=True, exist_ok=True)
    artifact = acquire_artifact(
        download_url, artifact_path,
        expected_size=policy.artifact_size,
        expected_sha256=policy.artifact_sha256,
        allow_loopback_http=allow_loopback_http,
    )
    staged = stage_verified_zip(
        Path(artifact), staged_root, policy,
        executable_relative=manifest.executable,
    )
    return PreparedUpdate(transaction_id, Path(artifact), staged)
