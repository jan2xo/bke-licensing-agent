import json
from pathlib import Path

import pytest

from bke_licensing_agent.discovery.paths import parse_discovery_paths, resolve_manifest_entry
from bke_licensing_agent.discovery.scanner import scan_locations


def test_parse_discovery_paths_returns_default_locations(monkeypatch):
    monkeypatch.delenv("BKE_DISCOVERY_PATHS", raising=False)

    paths = parse_discovery_paths(None)

    assert len(paths) > 0
    assert all(isinstance(path, Path) for path in paths)


def test_resolve_manifest_entry_rejects_path_traversal(tmp_path: Path):
    manifest_dir = tmp_path / "product"
    manifest_dir.mkdir()

    with pytest.raises(ValueError, match="escape"):
        resolve_manifest_entry("../evil.exe", manifest_dir)


def test_scan_locations_returns_discovered_product(tmp_path: Path):
    product_dir = tmp_path / "product"
    product_dir.mkdir()
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
    manifest_path = product_dir / "bke.manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    (product_dir / "AIRSTACK.exe").write_text("", encoding="utf-8")

    discovered = scan_locations([product_dir])

    assert len(discovered) == 1
    discovered_product = discovered[0]
    assert discovered_product.manifest["productId"] == "airstack"
    assert discovered_product.entry_point_path == product_dir / "AIRSTACK.exe"
