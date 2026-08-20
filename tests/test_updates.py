from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bke_licensing_agent.updates.orchestrator import UpdateOrchestrator
from bke_updater_core.models import Decision, ProductManifest


def _policy(private_key: Ed25519PrivateKey, *, revision: int = 1, product_id: str = "mock-product") -> dict:
    unsigned = {
        "schema": "bke.update-policy.v1",
        "product_id": product_id,
        "current_version": "1.0.0",
        "latest_version": "1.1.0",
        "minimum_supported_version": "1.0.0",
        "channel": "stable",
        "platform": "linux",
        "architecture": "x64",
        "release_id": "release-1",
        "artifact_id": "artifact-1",
        "artifact_sha256": "a" * 64,
        "artifact_size": 12,
        "content_type": "application/octet-stream",
        "published_at": "2026-08-20T00:00:00Z",
        "issued_at": "2026-08-20T00:00:00Z",
        "revision": revision,
        "signing_key_id": "test-key",
        "algorithm": "Ed25519",
    }
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return {**unsigned, "signature": base64.b64encode(private_key.sign(canonical)).decode()}


@pytest.fixture
def manifest(tmp_path: Path) -> ProductManifest:
    root = tmp_path / "product"
    root.mkdir()
    executable = root / "product.bin"
    executable.write_text("v1")
    return ProductManifest(
        product_id="mock-product",
        version="1.0.0",
        platform="linux",
        architecture="x64",
        executable="product.bin",
        install_root=root,
        update_channel="stable",
    )


def test_verified_policy_decision_and_cache(manifest: ProductManifest, tmp_path: Path) -> None:
    private_key = Ed25519PrivateKey.generate()
    agent = UpdateOrchestrator({"test-key": private_key.public_key().public_bytes_raw()}, tmp_path / "state")
    policy = agent.verify_policy(_policy(private_key), manifest)
    assert agent.decide(manifest, policy) is Decision.UPDATE_AVAILABLE
    cache = tmp_path / "policy.json"
    agent.cache_verified(cache, policy, "2026-08-20T00:00:00Z")
    assert agent.offline_decision(manifest, agent.load_cached(cache)) is Decision.UPDATE_AVAILABLE


def test_policy_tampering_unknown_key_and_stale_revision_fail_closed(manifest: ProductManifest, tmp_path: Path) -> None:
    private_key = Ed25519PrivateKey.generate()
    agent = UpdateOrchestrator({"test-key": private_key.public_key().public_bytes_raw()}, tmp_path / "state")
    policy = _policy(private_key)
    agent.verify_policy(policy, product_id=manifest.product_id) if False else None
    policy["latest_version"] = "9.9.9"
    with pytest.raises(ValueError):
        agent.verify_policy(policy, manifest)
    valid = _policy(private_key)
    agent.verify_policy(valid, manifest)
    with pytest.raises(ValueError):
        agent.verify_policy({**valid, "signing_key_id": "unknown"}, manifest)
    with pytest.raises(ValueError):
        agent.verify_policy(_policy(private_key, revision=1), manifest, last_revision=1)


def test_required_version_is_enforced(manifest: ProductManifest, tmp_path: Path) -> None:
    private_key = Ed25519PrivateKey.generate()
    agent = UpdateOrchestrator({"test-key": private_key.public_key().public_bytes_raw()}, tmp_path / "state")
    required = _policy(private_key)
    required["minimum_supported_version"] = "1.1.0"
    unsigned = {k: v for k, v in required.items() if k != "signature"}
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    required["signature"] = base64.b64encode(private_key.sign(canonical)).decode()
    verified = agent.verify_policy(required, manifest)
    assert agent.decide(manifest, verified) is Decision.UPDATE_REQUIRED
