import json
from pathlib import Path
from threading import Thread
from time import monotonic

from bke_licensing_agent.config import DEFAULT_AGENT_PORT, get_agent_port
from bke_licensing_agent.runtime import InstalledAgentRuntime, _load_trusted_keys
from bke_licensing_agent.storage.database import Database


def _install_product(root: Path, product_id: str = "fixture-product") -> Path:
    product = root / "Product"
    product.mkdir(parents=True)
    manifest = {
        "schemaVersion": 1,
        "productId": product_id,
        "displayName": "Fixture Product",
        "version": "1.0.0",
        "entryPoint": "product.exe",
        "updateChannel": "stable",
        "minimumAgentVersion": "1.0.0",
        "platform": "windows",
        "architecture": "x64",
    }
    path = product / "bke.manifest.json"
    path.write_text(json.dumps(manifest))
    (product / "product.exe").write_bytes(b"fixture")
    return path


def test_installed_runtime_denies_unknown_product(tmp_path: Path):
    database = Database(tmp_path / "agent.db")
    runtime = InstalledAgentRuntime(database=database, port=0)
    try:
        result = runtime.authorize({
            "product_id": "missing-product",
            "version": "1.0.0",
            "installation_id": "installation-1",
        })
        assert result == {"authorized": False, "reason": "unknown_product_or_version"}
    finally:
        runtime.close()


def test_authorize_miss_refreshes_installed_product_and_returns_activation_required(
    tmp_path: Path, monkeypatch
):
    root = tmp_path / "Program Files" / "BKE Digital Solutions"
    _install_product(root)
    monkeypatch.setenv("BKE_DISCOVERY_PATHS", str(root))
    runtime = InstalledAgentRuntime(database=Database(tmp_path / "agent.db"), port=0)
    try:
        thread = Thread(target=runtime.serve_forever)
        thread.start()
        deadline = monotonic() + 5
        while runtime._server is None and monotonic() < deadline:
            runtime._stop_event.wait(0.01)
        assert runtime.database.list_discovered_products()[0].product_id == "fixture-product"
        result = runtime.authorize({
            "product_id": "fixture-product",
            "version": "1.0.0",
            "installation_id": "installation-1",
        })
        assert result["reason"] == "activation_required"
        assert str(result["license_center_url"]).startswith("http://127.0.0.1:")
    finally:
        runtime.close()
        thread.join(timeout=3)


def test_product_installed_after_start_is_discovered_on_first_miss(tmp_path: Path, monkeypatch):
    root = tmp_path / "installed"
    root.mkdir()
    monkeypatch.setenv("BKE_DISCOVERY_PATHS", str(root))
    runtime = InstalledAgentRuntime(database=Database(tmp_path / "agent.db"), port=0)
    try:
        runtime._refresh_discovered_products()
        _install_product(root, "late-product")
        result = runtime.authorize({
            "product_id": "late-product",
            "version": "1.0.0",
            "installation_id": "installation-1",
        })
        assert result["reason"] == "activation_required"
    finally:
        runtime.close()


def test_refresh_removes_uninstalled_product_from_discovery_cache(tmp_path: Path, monkeypatch):
    root = tmp_path / "installed"
    manifest_path = _install_product(root)
    monkeypatch.setenv("BKE_DISCOVERY_PATHS", str(root))
    runtime = InstalledAgentRuntime(database=Database(tmp_path / "agent.db"), port=0)
    try:
        runtime._refresh_discovered_products()
        assert len(runtime.database.list_discovered_products()) == 1
        manifest_path.unlink()
        runtime._refresh_discovered_products()
        assert runtime.database.list_discovered_products() == []
    finally:
        runtime.close()


def test_cached_product_with_missing_entry_point_fails_closed(tmp_path: Path, monkeypatch):
    root = tmp_path / "installed"
    _install_product(root)
    monkeypatch.setenv("BKE_DISCOVERY_PATHS", str(root))
    runtime = InstalledAgentRuntime(database=Database(tmp_path / "agent.db"), port=0)
    try:
        runtime._refresh_discovered_products()
        (root / "Product" / "product.exe").unlink()
        result = runtime.authorize({
            "product_id": "fixture-product",
            "version": "1.0.0",
            "installation_id": "installation-1",
        })
        assert result == {"authorized": False, "reason": "unknown_product_or_version"}
        assert runtime.database.list_discovered_products() == []
    finally:
        runtime.close()


def test_trusted_key_loader_uses_filename_stem_as_key_id(tmp_path: Path):
    (tmp_path / "authority-v1.pem").write_text("PUBLIC KEY")
    (tmp_path / "ignore.txt").write_text("not a key")
    assert _load_trusted_keys(tmp_path) == {"authority-v1": "PUBLIC KEY"}


def test_default_agent_port_is_stable(monkeypatch):
    monkeypatch.delenv("BKE_AGENT_PORT", raising=False)
    assert get_agent_port() == DEFAULT_AGENT_PORT
