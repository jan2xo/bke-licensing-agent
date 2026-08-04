import json
from pathlib import Path

import pytest

from bke_licensing_agent.manifest.loader import load_manifest
from bke_licensing_agent.manifest.validator import validate_manifest


def test_valid_manifest(tmp_path: Path):
    manifest = {
        "schemaVersion": 1,
        "productId": "airstack",
        "displayName": "AIRSTACK",
        "publisher": "BKE Digital Solutions",
        "version": "1.0.0",
        "entryPoint": "AIRSTACK.exe",
        "icon": "assets/airstack.ico",
        "updateChannel": "stable",
        "minimumAgentVersion": "1.0.0",
        "platform": "windows",
        "architecture": "x64",
    }
    manifest_path = tmp_path / "bke.manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    loaded = load_manifest(manifest_path)
    validate_manifest(loaded)
    assert loaded["productId"] == "airstack"


def test_invalid_manifest_missing_required_field(tmp_path: Path):
    manifest = {
        "schemaVersion": 1,
        "productId": "airstack",
        "displayName": "AIRSTACK",
        "version": "1.0.0",
        "updateChannel": "stable",
        "minimumAgentVersion": "1.0.0",
        "platform": "windows",
        "architecture": "x64",
    }
    manifest_path = tmp_path / "bke.manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    loaded = load_manifest(manifest_path)
    with pytest.raises(ValueError, match="entryPoint"):
        validate_manifest(loaded)
