from __future__ import annotations

import base64
import json
from pathlib import Path
from types import SimpleNamespace

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bke_licensing_agent.api.models import UpdateDiscoveryResponse
from bke_licensing_agent.updates.discovery import UpdateDiscoveryCoordinator


def _fixture(tmp_path: Path, response: UpdateDiscoveryResponse):
    private = Ed25519PrivateKey.generate()
    public_pem = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    root = tmp_path / "product"; root.mkdir(); (root / "run.exe").write_text("v1")
    record = SimpleNamespace(product_root=str(root))
    manifest = SimpleNamespace(productId="p", version="1.0.0", platform="windows", architecture="x64",
                               entryPoint="run.exe", updateChannel="stable")
    lease = SimpleNamespace(signed_payload="{}", signed_signature="sig", key_id="k", signed_algorithm="Ed25519")
    class Client:
        def check_update(self, _request): return response
    coordinator = UpdateDiscoveryCoordinator(
        state_root=tmp_path / "state", platform_client=Client(), trusted_keys=lambda: {"k": public_pem},
        resolve_product=lambda _p, _v: (record, manifest), resolve_lease=lambda _p, _v: lease,
    )
    return coordinator, private


def _signed_policy(private: Ed25519PrivateKey) -> dict:
    unsigned = {"schema":"bke.update-policy.v1","product_id":"p","current_version":"1.0.0",
        "latest_version":"2.0.0","minimum_supported_version":"1.0.0","channel":"stable",
        "platform":"windows","architecture":"x64","release_id":"r2","artifact_id":"a2",
        "artifact_sha256":"a"*64,"artifact_size":12,"content_type":"application/octet-stream",
        "published_at":"2026-08-20T00:00:00Z","issued_at":"2026-08-20T00:00:00Z","revision":2,
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


def test_same_revision_with_changed_policy_is_rejected(tmp_path):
    coordinator, private = _fixture(tmp_path, UpdateDiscoveryResponse(status="up_to_date"))
    policy = _signed_policy(private)
    coordinator.client.check_update = lambda _request: UpdateDiscoveryResponse(
        status="update_available", policy=policy, download_url="https://example.invalid/grant")
    assert coordinator.refresh("p", "1.0.0")["state"] == "update_available"
    changed = {**policy, "issued_at": "2026-08-21T00:00:00Z"}
    coordinator.client.check_update = lambda _request: UpdateDiscoveryResponse(
        status="update_available", policy=changed, download_url="https://example.invalid/grant")
    assert coordinator.refresh("p", "1.0.0")["state"] == "refresh_failed"


def test_malformed_or_offline_refresh_never_becomes_no_update(tmp_path):
    coordinator, _ = _fixture(tmp_path, UpdateDiscoveryResponse(status="up_to_date"))
    coordinator.client.check_update = lambda _request: (_ for _ in ()).throw(TimeoutError())
    assert coordinator.refresh("p", "1.0.0")["state"] == "refresh_failed"
