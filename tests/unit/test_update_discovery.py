from __future__ import annotations

import base64
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bke_licensing_agent.api.errors import (
    AuthorizationDeniedError,
    InvalidServerResponseError,
    NetworkUnavailableError,
    ServerUnavailableError,
    TlsFailureError,
    UpdateProtocolError,
    UpdateVerificationError,
)
from bke_licensing_agent.api.models import UpdateDiscoveryResponse
from bke_licensing_agent.updates.discovery import RefreshPolicy, UpdateDiscoveryCoordinator


def _fixture(tmp_path: Path, response: UpdateDiscoveryResponse, *, clock=None, policy=None):
    private = Ed25519PrivateKey.generate()
    public_pem = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    root = tmp_path / "product"; root.mkdir(exist_ok=True); (root / "run.exe").write_text("v1")
    record = SimpleNamespace(product_root=str(root))
    manifest = SimpleNamespace(productId="p", version="1.0.0", platform="windows", architecture="x64",
                               entryPoint="run.exe", updateChannel="stable")
    lease = SimpleNamespace(signed_payload="{}", signed_signature="sig", key_id="k", signed_algorithm="Ed25519")
    class Client:
        def check_update(self, _request): return response
    coordinator = UpdateDiscoveryCoordinator(
        state_root=tmp_path / "state", platform_client=Client(), trusted_keys=lambda: {"k": public_pem},
        resolve_product=lambda _p, _v: (record, manifest), resolve_lease=lambda _p, _v: lease,
        clock=clock or (lambda: datetime.now(timezone.utc)), policy=policy,
    )
    return coordinator, private


def _signed_policy(private: Ed25519PrivateKey, *, revision=2, latest="2.0.0", content_type="application/vnd.bke.update-package+zip") -> dict:
    unsigned = {"schema":"bke.update-policy.v1","product_id":"p","current_version":"1.0.0",
        "latest_version":latest,"minimum_supported_version":"1.0.0","channel":"stable",
        "platform":"windows","architecture":"x64","release_id":"r2","artifact_id":"a2",
        "artifact_sha256":"a"*64,"artifact_size":12,"content_type":content_type,
        "published_at":"2026-08-20T00:00:00Z","issued_at":"2026-08-20T00:00:00Z","revision":revision,
        "signing_key_id":"k","algorithm":"Ed25519"}
    raw=json.dumps(unsigned,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
    return {**unsigned,"signature":base64.b64encode(private.sign(raw)).decode()}


def test_online_no_update_is_cached_without_policy(tmp_path):
    coordinator, _ = _fixture(tmp_path, UpdateDiscoveryResponse(status="up_to_date"))
    assert coordinator.refresh("p", "1.0.0")["state"] == "up_to_date"
    assert coordinator.status("p", "1.0.0")["state"] == "up_to_date"


def test_verified_update_is_cached_and_reported(tmp_path):
    coordinator, private = _fixture(tmp_path, UpdateDiscoveryResponse(status="up_to_date"))
    coordinator.client.check_update = lambda _request: UpdateDiscoveryResponse(
        status="update_available", policy=_signed_policy(private), download_url="https://example.invalid/grant")
    assert coordinator.refresh("p", "1.0.0")["state"] == "update_available"
    assert coordinator.status("p", "1.0.0")["latest_version"] == "2.0.0"
    assert coordinator.refresh("p", "1.0.0")["state"] == "update_available"


def test_non_updater_payload_policy_is_rejected_as_verification_failure(tmp_path):
    coordinator, private = _fixture(tmp_path, UpdateDiscoveryResponse(status="up_to_date"))
    coordinator.client.check_update = lambda _request: UpdateDiscoveryResponse(
        status="update_available", policy=_signed_policy(private, content_type="application/vnd.microsoft.portable-executable"),
        download_url="https://example.invalid/grant")
    result = coordinator.refresh("p", "1.0.0")
    assert result["state"] == "refresh_failed"
    assert result["error"] == "verification_failure"


def test_same_revision_with_changed_policy_is_rejected_as_verification_failure(tmp_path):
    coordinator, private = _fixture(tmp_path, UpdateDiscoveryResponse(status="up_to_date"))
    policy = _signed_policy(private)
    coordinator.client.check_update = lambda _request: UpdateDiscoveryResponse(
        status="update_available", policy=policy, download_url="https://example.invalid/grant")
    assert coordinator.refresh("p", "1.0.0")["state"] == "update_available"
    changed = {**policy, "issued_at": "2026-08-21T00:00:00Z"}
    coordinator.client.check_update = lambda _request: UpdateDiscoveryResponse(
        status="update_available", policy=changed, download_url="https://example.invalid/grant")
    result = coordinator.refresh("p", "1.0.0")
    assert result["state"] == "refresh_failed"
    assert result["error"] == "verification_failure"


@pytest.mark.parametrize("error, expected", [
    (NetworkUnavailableError("offline"), "transport_failure"),
    (TlsFailureError("tls"), "verification_failure"),
    (InvalidServerResponseError("bad"), "malformed_response"),
    (UpdateProtocolError("protocol"), "protocol_failure"),
    (UpdateVerificationError("verify"), "verification_failure"),
    (AuthorizationDeniedError("denied"), "policy_denied"),
    (ServerUnavailableError("server"), "provider_unavailable"),
])
def test_remote_failures_keep_their_first_broken_boundary(tmp_path, error, expected):
    coordinator, _ = _fixture(tmp_path, UpdateDiscoveryResponse(status="up_to_date"))
    coordinator.client.check_update = lambda _request: (_ for _ in ()).throw(error)
    result = coordinator.refresh("p", "1.0.0")
    assert result["state"] == "refresh_failed"
    assert result["error"] == expected
    assert coordinator.status("p", "1.0.0")["error"] == expected


def test_missing_product_and_entitlement_are_not_collapsed(tmp_path):
    coordinator, _ = _fixture(tmp_path, UpdateDiscoveryResponse(status="up_to_date"))
    coordinator.resolve_product = lambda _p, _v: None
    assert coordinator.refresh("p", "1.0.0")["error"] == "invalid_product_context"
    coordinator, _ = _fixture(tmp_path, UpdateDiscoveryResponse(status="up_to_date"))
    coordinator.resolve_lease = lambda _p, _v: None
    assert coordinator.refresh("p", "1.0.0")["error"] == "policy_denied"


def test_later_is_persisted_for_same_release_and_new_release_resets_it(tmp_path):
    now = [datetime(2026, 8, 26, tzinfo=timezone.utc)]
    coordinator, private = _fixture(
        tmp_path, UpdateDiscoveryResponse(status="up_to_date"), clock=lambda: now[0],
        policy=RefreshPolicy(remind_after=timedelta(hours=24)),
    )
    coordinator.client.check_update = lambda _request: UpdateDiscoveryResponse(
        status="update_available", policy=_signed_policy(private), download_url="https://example.invalid/grant")
    assert coordinator.refresh("p", "1.0.0")["state"] == "update_available"
    assert coordinator.dismiss("p", "1.0.0", "2.0.0")["state"] == "suppressed_update"
    assert coordinator.status("p", "1.0.0")["state"] == "suppressed_update"
    now[0] += timedelta(hours=25)
    assert coordinator.status("p", "1.0.0")["state"] == "stale_update"


def test_queue_refresh_deduplicates_concurrent_requests(tmp_path):
    coordinator, _ = _fixture(tmp_path, UpdateDiscoveryResponse(status="up_to_date"))
    calls = []
    def slow(_request):
        calls.append(1); time.sleep(0.15); return UpdateDiscoveryResponse(status="up_to_date")
    coordinator.client.check_update = slow
    assert coordinator.queue_refresh("p", "1.0.0") is True
    assert coordinator.queue_refresh("p", "1.0.0") is False
    time.sleep(0.3)
    assert calls == [1]


def test_failure_backoff_is_bounded_and_resets_on_success(tmp_path):
    coordinator, _ = _fixture(tmp_path, UpdateDiscoveryResponse(status="up_to_date"),
        policy=RefreshPolicy(interval=timedelta(hours=6), initial_backoff=timedelta(minutes=1), maximum_backoff=timedelta(minutes=5)))
    coordinator.client.check_update = lambda _request: (_ for _ in ()).throw(NetworkUnavailableError("offline"))
    coordinator.refresh("p", "1.0.0")
    assert 50 <= coordinator.next_delay() <= 70
    coordinator.client.check_update = lambda _request: UpdateDiscoveryResponse(status="up_to_date")
    coordinator.refresh("p", "1.0.0")
    assert coordinator.next_delay() > 5 * 60
