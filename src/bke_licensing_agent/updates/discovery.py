"""Agent-owned remote update discovery, verified cache, suppression, and secret-free status."""
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

from ..api.errors import (
    AuthenticationExpiredError,
    AuthenticationRequiredError,
    AuthorizationDeniedError,
    ConflictError,
    InvalidServerResponseError,
    NetworkUnavailableError,
    RateLimitExceededError,
    ResourceNotFoundError,
    ServerUnavailableError,
    TlsFailureError,
    UnknownApiError,
    UnsupportedClientVersionError,
    UpdateProtocolError,
    UpdateVerificationError,
)
from ..api.models import UpdateDiscoveryRequest
from .orchestrator import UpdateOrchestrator

UPDATE_PACKAGE_CONTENT_TYPE = "application/vnd.bke.update-package+zip"


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
    initial_backoff: timedelta = timedelta(minutes=1)
    remind_after: timedelta = timedelta(hours=24)


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
        self._inflight_lock = threading.Lock()
        self._inflight: set[tuple[str, str]] = set()
        self._consecutive_failures = 0

    def _paths(self, product_id: str, version: str) -> tuple[Path, Path]:
        root = self.state_root / _safe(product_id) / _safe(version)
        return root / "policy.json", root / "status.json"

    def _suppression_path(self, product_id: str, version: str) -> Path:
        return self.state_root / _safe(product_id) / _safe(version) / "suppression.json"

    @staticmethod
    def _manifest(record, manifest) -> ProductManifest:
        return ProductManifest(
            manifest.productId, manifest.version, manifest.platform, manifest.architecture,
            manifest.entryPoint, Path(record.product_root), update_channel=manifest.updateChannel,
        )

    def _write_status(self, path: Path, document: dict[str, object]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")))
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        tmp.replace(path)

    def _mark_result(self, failed: bool) -> None:
        with self._inflight_lock:
            self._consecutive_failures = min(self._consecutive_failures + 1, 16) if failed else 0

    def _failed_refresh(self, status_path: Path, *, product_id: str, version: str,
                        attempted: datetime, error: str) -> dict[str, object]:
        previous = self._read_status(status_path)
        document = {**(previous or {}), "state": "refresh_failed", "product_id": product_id,
                    "current_version": version, "last_attempt_at": _iso(attempted), "error": error}
        self._write_status(status_path, document)
        self._mark_result(True)
        return document

    def queue_refresh(self, product_id: str, version: str) -> bool:
        """Start at most one concurrent refresh for a product/version pair."""
        key = (product_id, version)
        with self._inflight_lock:
            if key in self._inflight:
                return False
            self._inflight.add(key)

        def run() -> None:
            try:
                self.refresh(product_id, version)
            finally:
                with self._inflight_lock:
                    self._inflight.discard(key)

        threading.Thread(target=run, daemon=True, name=f"bke-update-{_safe(product_id)}").start()
        return True

    def refresh(self, product_id: str, version: str) -> dict[str, object]:
        with self._lock:
            policy_path, status_path = self._paths(product_id, version)
            attempted = self.clock()
            resolved = self.resolve_product(product_id, version)
            if resolved is None:
                return self._failed_refresh(
                    status_path, product_id=product_id, version=version,
                    attempted=attempted, error="invalid_product_context",
                )
            lease = self.resolve_lease(product_id, version)
            if lease is None:
                return self._failed_refresh(
                    status_path, product_id=product_id, version=version,
                    attempted=attempted, error="policy_denied",
                )
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
                    self._mark_result(False)
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
                if verified.content_type != UPDATE_PACKAGE_CONTENT_TYPE:
                    raise ValueError("signed policy does not authorize a BKE updater package")
                if orchestrator.decide(core_manifest, verified) not in {Decision.UPDATE_AVAILABLE, Decision.UPDATE_REQUIRED}:
                    raise ValueError("signed policy does not describe an update")
                orchestrator.cache_verified(policy_path, verified, _iso(attempted), core_manifest)
                document = {"state": "update_available", "product_id": product_id,
                            "current_version": version, "latest_version": verified.latest_version,
                            "release_id": verified.release_id, "revision": verified.revision,
                            "verified_at": _iso(attempted), "last_attempt_at": _iso(attempted)}
                self._write_status(status_path, document)
                self._mark_result(False)
                return document
            except TlsFailureError:
                return self._failed_refresh(status_path, product_id=product_id, version=version,
                                            attempted=attempted, error="verification_failure")
            except NetworkUnavailableError:
                return self._failed_refresh(status_path, product_id=product_id, version=version,
                                            attempted=attempted, error="transport_failure")
            except InvalidServerResponseError:
                return self._failed_refresh(status_path, product_id=product_id, version=version,
                                            attempted=attempted, error="malformed_response")
            except UpdateVerificationError:
                return self._failed_refresh(status_path, product_id=product_id, version=version,
                                            attempted=attempted, error="verification_failure")
            except UpdateProtocolError:
                return self._failed_refresh(status_path, product_id=product_id, version=version,
                                            attempted=attempted, error="protocol_failure")
            except AuthorizationDeniedError:
                return self._failed_refresh(status_path, product_id=product_id, version=version,
                                            attempted=attempted, error="policy_denied")
            except (ServerUnavailableError, RateLimitExceededError):
                return self._failed_refresh(status_path, product_id=product_id, version=version,
                                            attempted=attempted, error="provider_unavailable")
            except (AuthenticationRequiredError, AuthenticationExpiredError, ResourceNotFoundError,
                    ConflictError, UnsupportedClientVersionError, UnknownApiError):
                return self._failed_refresh(status_path, product_id=product_id, version=version,
                                            attempted=attempted, error="protocol_failure")
            except ValueError:
                return self._failed_refresh(status_path, product_id=product_id, version=version,
                                            attempted=attempted, error="verification_failure")
            except Exception:
                return self._failed_refresh(status_path, product_id=product_id, version=version,
                                            attempted=attempted, error="unknown")

    def dismiss(self, product_id: str, version: str, latest_version: str) -> dict[str, object]:
        status = self.status(product_id, version, apply_suppression=False)
        if status.get("state") not in {"update_available", "stale_update"} or status.get("latest_version") != latest_version:
            return {"state": "dismiss_rejected", "product_id": product_id, "current_version": version}
        now = self.clock()
        until = now + self.policy.remind_after
        document = {"latest_version": latest_version, "dismissed_at": _iso(now), "remind_after": _iso(until)}
        self._write_status(self._suppression_path(product_id, version), document)
        return {"state": "suppressed_update", "product_id": product_id, "current_version": version,
                "latest_version": latest_version, "suppressed_until": _iso(until)}

    def _read_status(self, path: Path) -> dict[str, object] | None:
        try:
            value = json.loads(path.read_text())
            return value if isinstance(value, dict) else None
        except (OSError, ValueError):
            return None

    def status(self, product_id: str, version: str, *, apply_suppression: bool = True) -> dict[str, object]:
        policy_path, status_path = self._paths(product_id, version)
        document = self._read_status(status_path)
        if document is None:
            return {"state": "never_checked", "product_id": product_id, "current_version": version}
        result = {key: document[key] for key in (
            "state", "product_id", "current_version", "latest_version", "verified_at", "last_attempt_at", "error"
        ) if key in document}
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
            if apply_suppression:
                suppression = self._read_status(self._suppression_path(product_id, version))
                if suppression and suppression.get("latest_version") == result.get("latest_version"):
                    try:
                        until = datetime.fromisoformat(str(suppression["remind_after"]).replace("Z", "+00:00"))
                        if self.clock() < until:
                            result["state"] = "suppressed_update"
                            result["suppressed_until"] = _iso(until)
                    except (KeyError, TypeError, ValueError):
                        pass
        return result

    def refresh_due(self, product_id: str, version: str) -> bool:
        status = self.status(product_id, version, apply_suppression=False)
        reference = status.get("last_attempt_at") or status.get("verified_at")
        if not isinstance(reference, str):
            return True
        try:
            last = datetime.fromisoformat(reference.replace("Z", "+00:00"))
        except ValueError:
            return True
        return self.clock() - last >= self.policy.interval

    def next_delay(self) -> float:
        with self._inflight_lock:
            failures = self._consecutive_failures
        base = self.policy.interval.total_seconds()
        if failures:
            retry = self.policy.initial_backoff.total_seconds() * (2 ** (failures - 1))
            base = min(retry, self.policy.maximum_backoff.total_seconds())
        return max(1.0, base * random.uniform(0.9, 1.1))
