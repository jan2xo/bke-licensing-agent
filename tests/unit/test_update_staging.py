from __future__ import annotations

import hashlib
import shutil
import zipfile
from pathlib import Path

import pytest

from bke_licensing_agent.updates import staging
from bke_updater_core.models import ProductManifest, SignedUpdatePolicy


def _policy(artifact: Path, *, content_type: str = staging.UPDATE_PACKAGE_CONTENT_TYPE) -> SignedUpdatePolicy:
    return SignedUpdatePolicy(
        schema="bke.update-policy.v1", product_id="p", current_version="1.0.0", latest_version="2.0.0",
        minimum_supported_version="1.0.0", channel="stable", platform="windows", architecture="x64",
        release_id="r2", artifact_id="a2", artifact_sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
        artifact_size=artifact.stat().st_size, content_type=content_type,
        published_at="2026-08-26T00:00:00Z", issued_at="2026-08-26T00:00:00Z", revision=2,
        signing_key_id="k", algorithm="Ed25519", signature="sig", raw={},
    )


def test_agent_prepares_verified_staged_tree_without_executing(tmp_path, monkeypatch):
    package = tmp_path / "source.zip"
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr("run.exe", b"v2")
        archive.writestr("bke.manifest.json", b"{}")
    install = tmp_path / "installed"; install.mkdir(); (install / "run.exe").write_bytes(b"v1")
    manifest = ProductManifest("p", "1.0.0", "windows", "x64", "run.exe", install)
    policy = _policy(package)

    def acquire(_url, destination, *, expected_size, expected_sha256, allow_loopback_http=False):
        assert expected_size == package.stat().st_size
        assert expected_sha256 == hashlib.sha256(package.read_bytes()).hexdigest()
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(package, destination)
        return destination

    monkeypatch.setattr(staging, "acquire_artifact", acquire)
    prepared = staging.prepare_staged_update(
        manifest=manifest, policy=policy, download_url="https://example.invalid/grant", state_root=tmp_path / "state")
    assert (prepared.staged_root / "run.exe").read_bytes() == b"v2"
    assert (install / "run.exe").read_bytes() == b"v1"


def test_agent_rejects_installer_executable_as_update_payload(tmp_path):
    artifact = tmp_path / "installer.exe"; artifact.write_bytes(b"installer")
    install = tmp_path / "installed"; install.mkdir(); (install / "run.exe").write_bytes(b"v1")
    manifest = ProductManifest("p", "1.0.0", "windows", "x64", "run.exe", install)
    with pytest.raises(ValueError, match="staged-tree"):
        staging.prepare_staged_update(
            manifest=manifest, policy=_policy(artifact, content_type="application/vnd.microsoft.portable-executable"),
            download_url="https://example.invalid/grant", state_root=tmp_path / "state")
