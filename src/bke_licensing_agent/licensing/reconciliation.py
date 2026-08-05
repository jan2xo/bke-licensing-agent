"""Online reconciliation of signed lease state with the platform authority."""

import threading
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Callable

from ..auth.errors import MissingSessionError
from ..api.errors import ResourceNotFoundError
from ..auth.session import SessionManager
from ..devices.identity import InstallationIdentity
from ..manifest.models import Manifest
from .lease import (
    LicenseLease,
    LeaseRevokedError,
    LeaseSupersededError,
    LeaseVerifier,
    LeaseVerificationError,
)
from .lease_storage import LeaseMetadataRepository


class ReconciliationState(StrEnum):
    UNCHANGED = "lease_unchanged"
    UPDATED = "lease_updated"
    REVOKED = "lease_revoked"
    SUPERSEDED = "lease_superseded"
    EXPIRED = "lease_expired"
    DELETED = "lease_deleted"
    INVALID = "lease_invalid"
    FAILED = "reconciliation_failed"


@dataclass(frozen=True)
class ReconciliationResult:
    state: ReconciliationState
    lease_id: str | None = None
    reason: str = ""


@dataclass
class _Flight:
    event: threading.Event
    result: ReconciliationResult | None = None
    error: Exception | None = None


class LeaseReconciliationService:
    def __init__(self, client: Any, sessions: SessionManager,
                 identity: InstallationIdentity, verifier: LeaseVerifier,
                 repository: LeaseMetadataRepository,
                 clock: Callable[[], Any]):
        self.client, self.sessions, self.identity = client, sessions, identity
        self.verifier, self.repository, self.clock = verifier, repository, clock
        self._condition = threading.Condition()
        self._flights: dict[tuple[str, str, int], _Flight] = {}
        self._versions: dict[tuple[str, str], int] = {}

    def reconcile(self, manifest: Manifest, device_id: str,
                  version: str | None = None) -> ReconciliationResult:
        if not manifest.is_validated:
            return ReconciliationResult(ReconciliationState.INVALID, reason="Manifest is not validated")
        self.sessions.current_session()
        generation = self.sessions.generation
        installation_id = self.identity.load_or_create()
        identity_generation = getattr(self.identity, "generation", 0)
        key = (manifest.productId, device_id, generation)
        operation_key = (manifest.productId, device_id)
        with self._condition:
            flight = self._flights.get(key)
            if flight is None:
                version_number = self._versions.get(operation_key, 0) + 1
                self._versions[operation_key] = version_number
                flight = _Flight(threading.Event())
                self._flights[key] = flight
                owner = True
            else:
                owner = False
                version_number = self._versions[operation_key]
        if not owner:
            flight.event.wait()
            if flight.error:
                raise flight.error
            if flight.result is None:
                raise RuntimeError("Reconciliation completed without a result")
            return flight.result
        try:
            flight.result = self._reconcile_remote(
                manifest, device_id, version, installation_id, generation,
                identity_generation, operation_key, version_number,
            )
        except Exception as exc:
            flight.error = exc
        finally:
            with self._condition:
                self._flights.pop(key, None)
                flight.event.set()
        if flight.error:
            raise flight.error
        if flight.result is None:
            raise RuntimeError("Reconciliation completed without a result")
        return flight.result

    refresh = reconcile

    def _reconcile_remote(self, manifest: Manifest, device_id: str,
                          version: str | None, installation_id: str,
                          generation: int, identity_generation: int,
                          operation_key: tuple[str, str], operation_version: int) -> ReconciliationResult:
        try:
            response = self.client.retrieve_lease(
                manifest.productId, self.sessions.access_token()
            )
        except ResourceNotFoundError:
            self._delete_current(manifest.productId)
            return ReconciliationResult(ReconciliationState.DELETED, reason="Lease not found")
        self._require_current(generation, identity_generation, operation_key, operation_version)
        try:
            lease = self.verifier.verify(response.model_dump())
        except LeaseRevokedError:
            self._delete_current(manifest.productId)
            return ReconciliationResult(ReconciliationState.REVOKED)
        except LeaseSupersededError:
            self._delete_current(manifest.productId)
            return ReconciliationResult(ReconciliationState.SUPERSEDED)
        except LeaseVerificationError as exc:
            return ReconciliationResult(ReconciliationState.INVALID, reason=str(exc))
        except Exception as exc:
            return ReconciliationResult(ReconciliationState.INVALID, reason="Malformed lease response")
        self._require_current(generation, identity_generation, operation_key, operation_version)
        if lease.product_id != manifest.productId or lease.installation_id != installation_id or lease.device_id != device_id:
            return ReconciliationResult(ReconciliationState.INVALID, lease.lease_id, "Lease identity mismatch")
        if version is not None and lease.version != version:
            return ReconciliationResult(ReconciliationState.INVALID, lease.lease_id, "Lease version mismatch")
        current = self.repository.load(lease.lease_id)
        latest = self.repository.latest(lease.product_id, lease.device_id)
        if latest is not None and lease.generation < latest.generation:
            return ReconciliationResult(ReconciliationState.INVALID, lease.lease_id, "Older lease generation")
        now = self.clock()
        if now >= lease.expires_at:
            self.repository.delete(lease.lease_id)
            self.repository.delete_product(manifest.productId)
            return ReconciliationResult(ReconciliationState.EXPIRED, lease.lease_id, "Lease expired")
        if current is not None and current.generation == lease.generation:
            return ReconciliationResult(ReconciliationState.UNCHANGED, lease.lease_id)
        self.repository.save(self.repository_metadata(lease, now))
        return ReconciliationResult(ReconciliationState.UPDATED, lease.lease_id)

    def _delete_current(self, product_id: str) -> None:
        # Metadata is keyed by lease ID; remove all cached rows for the product.
        self.repository.delete_product(product_id)

    def _require_current(self, generation: int, identity_generation: int,
                         operation_key: tuple[str, str], operation_version: int) -> None:
        if not self.sessions.is_generation_current(generation):
            raise MissingSessionError("Session changed during reconciliation")
        if getattr(self.identity, "generation", 0) != identity_generation:
            raise MissingSessionError("Installation identity changed during reconciliation")
        with self._condition:
            if self._versions.get(operation_key) != operation_version:
                raise MissingSessionError("A newer reconciliation superseded this operation")

    @staticmethod
    def repository_metadata(lease: LicenseLease, now: Any):
        from .lease import LeaseMetadata
        return LeaseMetadata(lease_id=lease.lease_id, product_id=lease.product_id,
            installation_id=lease.installation_id, device_id=lease.device_id,
            generation=lease.generation, status="verified", issuer=lease.issuer,
            issued_at=lease.issued_at, expires_at=lease.expires_at,
            key_id=lease.key_id, verified_at=now,
            server_revision=lease.server_revision)
