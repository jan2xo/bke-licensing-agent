"""Agent-owned remote update discovery, verified cache, and secret-free status."""
from __future__ import annotations

import json
import os
import random
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from bke_updater_core.models import Decision, ProductManifest

from ..api.models import UpdateDiscoveryRequest
from .orchestrator import UpdateOrchestrator


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _safe(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "-", value)[:128]


def raw_update_keys(keys: dict[str, str]) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    for key_id, value in keys.items():
        loaded = serialization.load_pem_public_key(value.encode())
        if isinstance(loaded, Ed25519PublicKey):
            result[key_id] = loaded.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return result


@dataclass(frozen=True)
class RefreshPolicy:
    interval: timedelta = timedelta(hours=6)
    stale_after: timedelta = timedelta(hours=24)
    initial_delay_seconds: float = 5.0
    maximum_backoff: timedelta = timedelta(hours=6)


class UpdateDiscoveryCoordinator:
    def __init__(self, *, state_root: Path, platform_client, trusted_keys: Callable[[], dict[str, str]],
                 resolve_product: Callable[[str, str], tuple[object, object] | None],
                 resolve_lease: Callable[[str, str], object | None], policy: RefreshPolicy | None = None,
                 clock: Callable[[], datetime] = _now):
        self.state_root = state_root
        self.client = platform_client
        self.trusted_keys = trusted_keys
        self.resolve_product = resolve_product
        self.resolve_lease = resolve_lease
        self.policy = policy or RefreshPolicy()
        self.clock = clock
        self._lock = threading.RLock()

    def _paths(self, product_id: str, version: str) -> tuple[Path, Path]:
        root = self.state_root / _safe(product_id) / _safe(version)
        return root / "policy.json", root / "status.json"

    @staticmethod
    def _manifest(record, manifest) -> ProductManifest:
        return ProductManifest(
            manifest.productId, manifest.version, manifest.platform, manifest.architecture,
            manifest.entryPoint, Path(record.product_root), update_channel=manifest.updateChannel,
        )

    def _write_status(self, path: Path, document: dict[str, object]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")))
        try: os.chmod(tmp, 0o600)
        except OSError: pass
        tmp.replace(path)

    def refresh(self, product_id: str, version: str) -> dict[str, object]:
        with self._lock:
            policy_path, status_path = self._paths(product_id, version)
            attempted = self.clock()
            resolved = self.resolve_product(product_id, version)
            lease = self.resolve_lease(product_id, version)
            if resolved is None or lease is None:
                document = {"state": "refresh_failed", "product_id": product_id, "current_version": version,
                            "last_attempt_at": _iso(attempted), "error": "product_or_entitlement_unavailable"}
                self._write_status(status_path, document)
                return document
            record, manifest = resolved
            envelope = {"payload": lease.signed_payload, "signature": lease.signed_signature,
                        "key_id": lease.key_id, "algorithm": lease.signed_algorithm}
            try:
                response = self.client.check_update(UpdateDiscoveryRequest(
                    lease=envelope, product_id=product_id, current_version=version,
                    platform=manifest.platform, architecture=manifest.architecture,
                    channel=manifest.updateChannel,
                ))
                if response.status == "up_to_date":
                    document = {"state": "up_to_date", "product_id": product_id, "current_version": version,
                                "verified_at": _iso(attempted), "last_attempt_at": _iso(attempted)}
                    self._write_status(status_path, document)
                    return document
                if response.policy is None or response.download_url is None:
                    raise ValueError("update response omitted signed policy or grant")
                core_manifest = self._manifest(record, manifest)
                orchestrator = UpdateOrchestrator(raw_update_keys(self.trusted_keys()), self.state_root / "core")
                cached = orchestrator.load_cached(policy_path)
                cached_policy = cached.get("policy") if cached else None
                incoming_revision = response.policy.get("revision")
                cached_revision = cached_policy.get("revision") if isinstance(cached_policy, dict) else None
                if incoming_revision == cached_revision:
                    if response.policy != cached_policy:
                        raise ValueError("policy changed without a revision increase")
                    verified = orchestrator.verify_policy(response.policy, core_manifest, last_revision=incoming_revision - 1)
                else:
                    verified = orchestrator.verify_policy(response.policy, core_manifest)
                if orchestrator.decide(core_manifest, verified) not in {Decision.UPDATE_AVAILABLE, Decision.UPDATE_REQUIRED}:
                    raise ValueError("signed policy does not describe an update")
                orchestrator.cache_verified(policy_path, verified, _iso(attempted), core_manifest)
                document = {"state": "update_available", "product_id": product_id,
                            "current_version": version, "latest_version": verified.latest_version,
                            "release_id": verified.release_id, "revision": verified.revision,
                            "verified_at": _iso(attempted), "last_attempt_at": _iso(attempted)}
                self._write_status(status_path, document)
                return document
            except Exception:
                previous = self._read_status(status_path)
                document = {**(previous or {}), "state": "refresh_failed", "product_id": product_id,
                            "current_version": version, "last_attempt_at": _iso(attempted),
                            "error": "remote_or_verification_failure"}
                self._write_status(status_path, document)
                return document

    def _read_status(self, path: Path) -> dict[str, object] | None:
        try:
            value = json.loads(path.read_text())
            return value if isinstance(value, dict) else None
        except (OSError, ValueError):
            return None

    def status(self, product_id: str, version: str) -> dict[str, object]:
        policy_path, status_path = self._paths(product_id, version)
        document = self._read_status(status_path)
        if document is None:
            return {"state": "never_checked", "product_id": product_id, "current_version": version}
        result = {key: document[key] for key in ("state", "product_id", "current_version", "latest_version", "verified_at", "last_attempt_at") if key in document}
        if document.get("latest_version") and policy_path.exists():
            resolved = self.resolve_product(product_id, version)
            if resolved is None:
                return {"state": "verification_failed", "product_id": product_id, "current_version": version}
            try:
                record, manifest = resolved
                orchestrator = UpdateOrchestrator(raw_update_keys(self.trusted_keys()), self.state_root / "core")
                cached = orchestrator.load_cached(policy_path)
                decision = orchestrator.offline_decision(self._manifest(record, manifest), cached)
                if decision not in {Decision.UPDATE_AVAILABLE, Decision.UPDATE_REQUIRED}:
                    raise ValueError("cached policy no longer offers an update")
            except Exception:
                return {"state": "verification_failed", "product_id": product_id, "current_version": version}
            verified_at = datetime.fromisoformat(str(document["verified_at"]).replace("Z", "+00:00"))
            result["state"] = "stale_update" if self.clock() - verified_at > self.policy.stale_after else "update_available"
        return result

    def refresh_due(self, product_id: str, version: str) -> bool:
        status = self.status(product_id, version)
        reference = status.get("last_attempt_at") or status.get("verified_at")
        if not isinstance(reference, str): return True
        try: last = datetime.fromisoformat(reference.replace("Z", "+00:00"))
        except ValueError: return True
        return self.clock() - last >= self.policy.interval

    def next_delay(self) -> float:
        return max(1.0, self.policy.interval.total_seconds() * random.uniform(0.9, 1.1))
