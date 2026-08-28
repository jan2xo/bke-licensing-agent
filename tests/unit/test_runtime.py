from pathlib import Path

from bke_updater_core.models import TransactionState
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


def test_installed_runtime_rejects_native_center_for_unknown_product(tmp_path: Path):
    database = Database(tmp_path / "agent.db")
    runtime = InstalledAgentRuntime(database=database, port=0)
    try:
        result = runtime.open_license_center({
            "product_id": "missing-product", "version": "1.0.0",
            "installation_id": "installation-1", "correlation_id": "corr-1",
        })
        assert result == {
            "outcome": "invalid_product_context", "reason": "invalid product context",
            "correlation_id": "corr-1", "authorization_changed": False,
        }
    finally:
        runtime.close()


def test_update_center_hands_verified_available_update_to_privileged_execution(tmp_path: Path, monkeypatch):
    database = Database(tmp_path / "agent.db")
    runtime = InstalledAgentRuntime(database=database, port=0)
    calls = []
    monkeypatch.setattr(runtime.update_discovery, "status", lambda *_args, **_kwargs: {
        "state": "update_available", "latest_version": "2.0.0",
    })
    monkeypatch.setattr("bke_licensing_agent.runtime.execute_installed_product_update",
                        lambda owner, product_id, version: calls.append((owner, product_id, version)) or TransactionState.STAGED)
    try:
        result = runtime.open_update_center({"product_id": "bke-demo", "version": "1.0.0", "correlation_id": "corr-2"})
        assert result == {"outcome": "update_started", "reason": "staged", "correlation_id": "corr-2"}
        assert calls == [(runtime, "bke-demo", "1.0.0")]
    finally:
        runtime.close()


def test_update_center_fails_closed_when_privileged_handoff_rejects(tmp_path: Path, monkeypatch):
    database = Database(tmp_path / "agent.db")
    runtime = InstalledAgentRuntime(database=database, port=0)
    monkeypatch.setattr(runtime.update_discovery, "status", lambda *_args, **_kwargs: {
        "state": "update_available", "latest_version": "2.0.0",
    })
    def reject(*_args):
        raise ValueError("no trusted target")
    monkeypatch.setattr("bke_licensing_agent.runtime.execute_installed_product_update", reject)
    try:
        result = runtime.open_update_center({"product_id": "bke-demo", "version": "1.0.0", "correlation_id": "corr-3"})
        assert result == {"outcome": "update_failed", "reason": "privileged_update_verification_or_handoff_failed",
                          "correlation_id": "corr-3"}
    finally:
        runtime.close()


def test_trusted_key_loader_uses_filename_stem_as_key_id(tmp_path: Path):
    (tmp_path / "authority-v1.pem").write_text("PUBLIC KEY")
    (tmp_path / "ignore.txt").write_text("not a key")
    assert _load_trusted_keys(tmp_path) == {"authority-v1": "PUBLIC KEY"}


def test_default_agent_port_is_stable(monkeypatch):
    monkeypatch.delenv("BKE_AGENT_PORT", raising=False)
    assert get_agent_port() == DEFAULT_AGENT_PORT