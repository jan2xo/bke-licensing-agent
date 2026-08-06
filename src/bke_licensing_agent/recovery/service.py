"""Fail-closed startup recovery for untrusted local state."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Callable
import threading

from ..licensing.lease import LeaseMetadataCorruptError, LeaseMetadataPersistenceError
from ..storage.database import CURRENT_SCHEMA_VERSION


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
                 process_recovery: Callable[[], None] | None = None,
                 audit_recovery: Callable[[], None] | None = None,
                 reconnect: Callable[[], None] | None = None,
                 process_inspector: Callable[[int, dict[str, Any]], bool] | None = None,
                 audit_reconcile: Callable[[], None] | None = None,
                 identity_validate: Callable[[], None] | None = None,
                 refresh: Callable[[], None] | None = None,
                 reconcile: Callable[[], None] | None = None):
        self.database = database
        self.lease_repository = lease_repository
        self.process_recovery = process_recovery
        self.audit_recovery = audit_recovery
        self.reconnect = reconnect
        self.process_inspector = process_inspector
        self.audit_reconcile = audit_reconcile
        self.identity_validate = identity_validate
        self.refresh = refresh
        self.reconcile = reconcile
        self._reconnect_lock = threading.Lock()
        self._reconnect_running = False

    def startup(self) -> list[RecoveryResult]:
        results: list[RecoveryResult] = []
        if self.identity_validate is not None:
            try:
                self.identity_validate()
            except Exception as exc:
                return [RecoveryResult(RecoveryAction.MANUAL_INTERVENTION_REQUIRED, str(exc))]
        try:
            self._validate_database()
        except Exception as exc:
            return [RecoveryResult(RecoveryAction.MANUAL_INTERVENTION_REQUIRED, str(exc))]
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
        if self.audit_recovery is not None:
            try:
                self.audit_recovery()
                results.append(RecoveryResult(RecoveryAction.AUDIT_RECOVERED))
            except Exception as exc:
                results.append(RecoveryResult(RecoveryAction.RECOVERY_FAILED, str(exc)))
        if self.audit_reconcile is not None:
            try:
                self.audit_reconcile()
                results.append(RecoveryResult(RecoveryAction.AUDIT_RECOVERED))
            except Exception as exc:
                results.append(RecoveryResult(RecoveryAction.RECOVERY_FAILED, str(exc)))
        try:
            integrity = self.database.connection.execute("PRAGMA integrity_check").fetchone()[0]
            if integrity != "ok":
                results.append(RecoveryResult(RecoveryAction.CORRUPTED_STATE, "SQLite integrity check failed"))
        except Exception as exc:
            results.append(RecoveryResult(RecoveryAction.MANUAL_INTERVENTION_REQUIRED, str(exc)))
        if not results:
            results.append(RecoveryResult(RecoveryAction.RECOVERY_NOT_REQUIRED))
        return results

    def recover_process(self, pid: int, recorded: dict[str, Any]) -> RecoveryResult:
        if self.process_inspector is None:
            return RecoveryResult(RecoveryAction.MANUAL_INTERVENTION_REQUIRED, "No process identity inspector")
        try:
            if not self.process_inspector(pid, recorded):
                return RecoveryResult(RecoveryAction.PROCESS_RECOVERED, "PID identity mismatch; stale record cleaned")
            return RecoveryResult(RecoveryAction.PROCESS_RECOVERED, "Process identity matched recorded metadata")
        except Exception as exc:
            return RecoveryResult(RecoveryAction.MANUAL_INTERVENTION_REQUIRED, str(exc))

    def _validate_database(self) -> None:
        integrity = self.database.connection.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            raise RuntimeError("SQLite integrity failure")
        version = self.database.connection.execute(
            "SELECT version FROM schema_version"
        ).fetchone()[0]
        if version > CURRENT_SCHEMA_VERSION:
            raise RuntimeError("Unsupported database schema version")

    def recover_interrupted(self, operation: str, can_resume: bool = False) -> RecoveryResult:
        if operation not in {"refresh", "reconciliation", "startup", "launch"}:
            return RecoveryResult(RecoveryAction.MANUAL_INTERVENTION_REQUIRED, "Unknown operation")
        if can_resume and operation in {"refresh", "reconciliation"}:
            return RecoveryResult(RecoveryAction.RECOVERED, f"{operation} requires normal authoritative retry")
        return RecoveryResult(RecoveryAction.RECOVERED, f"{operation} rolled back safely")

    def reconnect_online(self) -> RecoveryResult:
        if self.reconnect is None:
            return RecoveryResult(RecoveryAction.RECOVERY_NOT_REQUIRED, "No reconnect boundary configured")
        with self._reconnect_lock:
            if self._reconnect_running:
                return RecoveryResult(RecoveryAction.RECOVERY_NOT_REQUIRED, "Reconnect already in progress")
            self._reconnect_running = True
        try:
            self.reconnect()
            if self.refresh is not None:
                self.refresh()
            if self.reconcile is not None:
                self.reconcile()
            return RecoveryResult(RecoveryAction.RECOVERED, "Reconnect requires normal refresh/reconciliation policy")
        except Exception as exc:
            return RecoveryResult(RecoveryAction.RECOVERY_FAILED, str(exc))
        finally:
            with self._reconnect_lock:
                self._reconnect_running = False

    def _validate_leases(self) -> None:
        repository = self.lease_repository
        if repository is None:
            return
        rows = self.database.connection.execute(
            "SELECT lease_id FROM lease_metadata"
        ).fetchall()
        for row in rows:
            repository.load(row[0])
