"""Fail-closed startup recovery for untrusted local state."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Callable

from ..licensing.lease import LeaseMetadataCorruptError, LeaseMetadataPersistenceError


class RecoveryAction(StrEnum):
    RECOVERED = "recovered"
    RECOVERY_NOT_REQUIRED = "recovery_not_required"
    RECOVERY_FAILED = "recovery_failed"
    MANUAL_INTERVENTION_REQUIRED = "manual_intervention_required"
    CORRUPTED_STATE = "corrupted_state"
    CACHE_REBUILT = "cache_rebuilt"
    AUDIT_RECOVERED = "audit_recovered"
    LEASE_RECOVERED = "lease_recovered"
    PROCESS_RECOVERED = "process_recovered"


@dataclass(frozen=True)
class RecoveryResult:
    action: RecoveryAction
    details: str = ""
    authorization_granted: bool = False


class RecoveryService:
    """Validates local state and removes only unsafe derived state."""

    def __init__(self, database: Any, lease_repository: Any | None = None,
                 process_recovery: Callable[[], None] | None = None):
        self.database = database
        self.lease_repository = lease_repository
        self.process_recovery = process_recovery

    def startup(self) -> list[RecoveryResult]:
        results: list[RecoveryResult] = []
        if self.lease_repository is not None:
            try:
                self._validate_leases()
                results.append(RecoveryResult(RecoveryAction.LEASE_RECOVERED))
            except (LeaseMetadataCorruptError, LeaseMetadataPersistenceError) as exc:
                results.append(RecoveryResult(RecoveryAction.CORRUPTED_STATE, str(exc)))
            except Exception as exc:
                results.append(RecoveryResult(RecoveryAction.RECOVERY_FAILED, str(exc)))
        if self.process_recovery is not None:
            try:
                self.process_recovery()
                results.append(RecoveryResult(RecoveryAction.PROCESS_RECOVERED))
            except Exception as exc:
                results.append(RecoveryResult(RecoveryAction.RECOVERY_FAILED, str(exc)))
        if not results:
            results.append(RecoveryResult(RecoveryAction.RECOVERY_NOT_REQUIRED))
        return results

    def _validate_leases(self) -> None:
        repository = self.lease_repository
        if repository is None:
            return
        rows = self.database.connection.execute(
            "SELECT lease_id FROM lease_metadata"
        ).fetchall()
        for row in rows:
            repository.load(row[0])
