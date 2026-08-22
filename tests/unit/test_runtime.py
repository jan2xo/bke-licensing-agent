from pathlib import Path

from bke_licensing_agent.config import DEFAULT_AGENT_PORT, get_agent_port
from bke_licensing_agent.runtime import InstalledAgentRuntime, _load_trusted_keys
from bke_licensing_agent.storage.database import Database


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


def test_trusted_key_loader_uses_filename_stem_as_key_id(tmp_path: Path):
    (tmp_path / "authority-v1.pem").write_text("PUBLIC KEY")
    (tmp_path / "ignore.txt").write_text("not a key")
    assert _load_trusted_keys(tmp_path) == {"authority-v1": "PUBLIC KEY"}


def test_default_agent_port_is_stable(monkeypatch):
    monkeypatch.delenv("BKE_AGENT_PORT", raising=False)
    assert get_agent_port() == DEFAULT_AGENT_PORT
