"""Deterministic lease refresh policy and replay protection."""

import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from .lease import LeaseVerificationError
from .reconciliation import LeaseReconciliationService, ReconciliationState


class RefreshState(StrEnum):
    NO_REFRESH_REQUIRED = "no_refresh_required"
    REFRESHED = "refreshed"
    UNCHANGED = "unchanged"
    REPLAY_REJECTED = "replay_rejected"
    STALE_REJECTED = "stale_rejected"
    REVOKED = "revoked"
    EXPIRED = "expired"
    DELETED = "deleted"
    FAILED = "failed"


@dataclass(frozen=True)
class RefreshResult:
    state: RefreshState
    lease_id: str | None = None
    reason: str = ""


class LeaseRefreshService:
    def __init__(self, reconciliation: LeaseReconciliationService,
                 threshold: timedelta = timedelta(hours=1)):
        self.reconciliation = reconciliation
        self.threshold = threshold
        self._lock = threading.Lock()
        self._inflight: dict[tuple[str, str, int], threading.Event] = {}
        self._results: dict[tuple[str, str, int], RefreshResult] = {}

    def should_refresh(self, product_id: str, device_id: str) -> bool:
        current = self.reconciliation.repository.latest(product_id, device_id)
        if current is None:
            return True
        return current.expires_at - self.reconciliation.clock() <= self.threshold

    def refresh(self, manifest, device_id: str, version: str | None = None) -> RefreshResult:
        generation = self.reconciliation.sessions.generation
        key = (manifest.productId, device_id, generation)
        if not self.should_refresh(manifest.productId, device_id):
            return RefreshResult(RefreshState.NO_REFRESH_REQUIRED)
        with self._lock:
            event = self._inflight.get(key)
            if event is None:
                event = threading.Event()
                self._inflight[key] = event
                owner = True
            else:
                owner = False
        if not owner:
            event.wait()
            return self._results[key]
        try:
            reconciliation_result = self.reconciliation.reconcile(manifest, device_id, version)
            mapping = {
                ReconciliationState.UPDATED: RefreshState.REFRESHED,
                ReconciliationState.UNCHANGED: RefreshState.UNCHANGED,
                ReconciliationState.REVOKED: RefreshState.REVOKED,
                ReconciliationState.SUPERSEDED: RefreshState.REPLAY_REJECTED,
                ReconciliationState.EXPIRED: RefreshState.EXPIRED,
                ReconciliationState.DELETED: RefreshState.DELETED,
                ReconciliationState.INVALID: RefreshState.STALE_REJECTED,
            }
            result = RefreshResult(
                mapping.get(reconciliation_result.state, RefreshState.FAILED),
                reconciliation_result.lease_id,
                reconciliation_result.reason,
            )
        except LeaseVerificationError as exc:
            result = RefreshResult(RefreshState.FAILED, reason=str(exc))
        except Exception as exc:
            result = RefreshResult(RefreshState.FAILED, reason=str(exc))
        with self._lock:
            self._results[key] = result
            self._inflight.pop(key, None)
            event.set()
        return result
