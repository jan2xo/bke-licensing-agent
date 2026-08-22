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


def test_windows_default_discovery_root_is_program_files(monkeypatch):
    monkeypatch.setattr("bke_licensing_agent.discovery.paths.sys.platform", "win32")
    monkeypatch.setenv("ProgramW6432", r"C:\Program Files")
    monkeypatch.delenv("BKE_DISCOVERY_PATHS", raising=False)

    assert parse_discovery_paths() == [Path(r"C:\Program Files") / "BKE Digital Solutions"]


def test_non_windows_default_discovery_paths_are_preserved(monkeypatch):
    monkeypatch.setattr("bke_licensing_agent.discovery.paths.sys.platform", "linux")
    monkeypatch.delenv("BKE_DISCOVERY_PATHS", raising=False)

    paths = parse_discovery_paths()

    assert Path.home() / "Applications" / "BKE" in paths
    assert Path("/Applications/BKE") in paths
    assert Path.home() / ".local" / "share" / "BKE" in paths


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


@pytest.mark.parametrize("invalid", ["manifest", "missing-entry", "entry-escape"])
def test_scan_locations_ignores_invalid_products(tmp_path: Path, invalid: str):
    product_dir = tmp_path / invalid
    product_dir.mkdir()
    manifest = {
        "schemaVersion": 1,
        "productId": f"fixture-{invalid}",
        "displayName": "Fixture",
        "version": "1.0.0",
        "entryPoint": "fixture.exe",
        "updateChannel": "stable",
        "minimumAgentVersion": "1.0.0",
        "platform": "windows",
        "architecture": "x64",
    }
    if invalid == "manifest":
        manifest.pop("productId")
    elif invalid == "entry-escape":
        manifest["entryPoint"] = "../outside.exe"
        (tmp_path / "outside.exe").write_bytes(b"fixture")
    (product_dir / "bke.manifest.json").write_text(json.dumps(manifest))
    if invalid == "manifest":
        (product_dir / "fixture.exe").write_bytes(b"fixture")

    assert scan_locations([product_dir]) == []
