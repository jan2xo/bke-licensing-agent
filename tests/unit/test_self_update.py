from pathlib import Path

import pytest

from bke_licensing_agent import self_update
from bke_licensing_agent.self_update import AgentSelfUpdateCoordinator, AgentSelfUpdateError


class _Response:
    def __init__(self, document):
        self._document = document

    def raise_for_status(self):
        return None

    def json(self):
        return self._document


def _document(current="0.0.0", latest="1.0.0", *, available=True, url=None):
    return {
        "productId": "bke-licensing-agent",
        "currentVersion": current,
        "latestVersion": latest,
        "updateAvailable": available,
        "downloadUrl": url if url is not None else (
            "https://github.com/jan2xo/bke-software-catalog/releases/download/"
            "bke-licensing-agent-v1.0.0/BKE-Licensing-Agent-1.0.0-Windows-x64.exe"
        ),
        "releaseNotes": "Stable BKE Licensing Agent 1.0.0",
        "required": False,
        "source": "bke-software-catalog",
    }


def _windows(monkeypatch):
    monkeypatch.setattr(self_update.os, "name", "nt")
    monkeypatch.setattr(self_update.platform, "machine", lambda: "AMD64")


def test_zero_version_discovers_stable_one(monkeypatch, tmp_path: Path):
    _windows(monkeypatch)
    monkeypatch.setattr(self_update.requests, "get", lambda *args, **kwargs: _Response(_document()))
    coordinator = AgentSelfUpdateCoordinator(
        state_root=tmp_path,
        platform_base_url="https://jl-bke.com",
        current_version="0.0.0",
    )

    offer = coordinator.check()

    assert offer is not None
    assert offer.current_version == "0.0.0"
    assert offer.latest_version == "1.0.0"
    assert offer.download_url.startswith(
        "https://github.com/jan2xo/bke-software-catalog/releases/download/"
    )


def test_current_agent_stays_quiet(monkeypatch, tmp_path: Path):
    _windows(monkeypatch)
    monkeypatch.setattr(
        self_update.requests,
        "get",
        lambda *args, **kwargs: _Response(_document(current="1.0.0", latest="1.0.0", available=False, url=None)),
    )
    coordinator = AgentSelfUpdateCoordinator(
        state_root=tmp_path,
        platform_base_url="https://jl-bke.com",
        current_version="1.0.0",
    )

    assert coordinator.check() is None


def test_agent_rejects_non_catalog_download(monkeypatch, tmp_path: Path):
    _windows(monkeypatch)
    monkeypatch.setattr(
        self_update.requests,
        "get",
        lambda *args, **kwargs: _Response(_document(url="https://example.com/agent.exe")),
    )
    coordinator = AgentSelfUpdateCoordinator(
        state_root=tmp_path,
        platform_base_url="https://jl-bke.com",
        current_version="0.0.0",
    )

    with pytest.raises(AgentSelfUpdateError, match="outside the BKE software catalog"):
        coordinator.check()
