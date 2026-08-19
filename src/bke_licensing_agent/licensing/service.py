import threading
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Any

from ..api.client import LicensingPlatformClient
from ..auth.errors import MissingSessionError
from ..auth.session import SessionManager
from ..devices.fingerprint import DeviceFingerprint, FINGERPRINT_SCHEMA_VERSION
from ..devices.identity import InstallationIdentity
from ..manifest.models import Manifest
from .errors import (ActivationDeniedError, DeviceLimitReachedError,
    DeviceRegistrationError, LicenseExpiredError, LicenseRevokedError,
    LicenseSuspendedError, NoLicenseAvailableError, ProductNotEntitledError,
    UnknownLicenseStateError)
from .errors import (ActivationPartialFailureError, DeactivationPartialFailureError,
    ManifestProvenanceError)
from .errors import ActivationVerificationError
from .models import (ActivationRequest, ActivationState,
    ActivationVerificationRequest, DeactivationRequest, DeviceMetadata,
    DeviceRegistrationRequest)
from .lease import LeaseVerifier
from .license_repository import ActiveLicenseBinding, VerifiedLicenseRecord, VerifiedLicenseRepository
from .authorization import AuthorizationDecision, AuthorizationService
from ..api.models import PlatformLeaseActivationRequest


@dataclass
class _ActivationFlight:
    event: threading.Event
    result: ActivationState | None = None
    error: Exception | None = None


class LicensingService:
    def __init__(self, client: LicensingPlatformClient, sessions: SessionManager,
                 identity: InstallationIdentity, fingerprint: DeviceFingerprint,
                 cache=None, agent_version="0.1.0", audit=None):
        self.client, self.sessions = client, sessions
        self.identity, self.fingerprint, self.cache, self.audit = identity, fingerprint, cache, audit
        self.agent_version = agent_version
        self._condition = threading.Condition()
        self._flights: dict[tuple[str, str, int], _ActivationFlight] = {}
        self._operation_versions: dict[tuple[str, str], int] = {}

    def activate_platform_lease(self, product: Manifest, license_key: str,
                                verifier: LeaseVerifier,
                                repository: VerifiedLicenseRepository) -> AuthorizationDecision:
        """Primary Digital Solutions activation path.

        The response is verified before either the license record or active binding
        is written. Legacy /devices and /activations calls are not used here.
        """
        if not product.is_validated:
            raise ManifestProvenanceError("Activation requires a manifest validated by the manifest pipeline")
        self.sessions.current_session()
        installation_id = self.identity.load_or_create()
        device_id = self.fingerprint.calculate()
        request = PlatformLeaseActivationRequest(
            licenseKey=license_key, installationId=installation_id,
            deviceId=device_id, operationId=str(uuid.uuid4()),
            operatingSystem=self.fingerprint.signals.get("platform"),
            architecture=self.fingerprint.signals.get("architecture"),
            label=None,
        )
        response = self.client.activate_platform_lease(request)
        lease = verifier.verify(response.lease)
        if lease.product_id != product.productId:
            raise ActivationVerificationError("Lease product identity mismatch")
        if lease.installation_id != installation_id:
            raise ActivationVerificationError("Lease installation identity mismatch")
        if lease.device_id != device_id:
            raise ActivationVerificationError("Lease device identity mismatch")
        if lease.version != product.version:
            raise ActivationVerificationError("Lease version identity mismatch")
        now = datetime.now(timezone.utc)
        record = VerifiedLicenseRecord(
            license_id=lease.license_id, product_id=lease.product_id,
            product_version=lease.version, installation_id=lease.installation_id,
            device_id=lease.device_id, lease_id=lease.lease_id,
            generation=lease.generation, server_revision=lease.server_revision,
            issued_at=lease.issued_at, not_before=lease.not_before,
            expires_at=lease.expires_at, status="verified", key_id=lease.key_id,
            created_at=now, updated_at=now,
        )
        repository.save(record)
        repository.bind(ActiveLicenseBinding(
            product_id=lease.product_id, installation_id=lease.installation_id,
            device_id=lease.device_id, active_license_id=lease.license_id,
            active_lease_id=lease.lease_id, generation=lease.generation,
            server_revision=lease.server_revision, binding_version=1,
            updated_at=now,
        ))
        decision = AuthorizationService().authorize_from_active_binding(
            product, installation_id, device_id, repository, lambda lease_id: lease if lease_id == lease.lease_id else None,
        )
        if not decision.authorized:
            raise ActivationDeniedError("Verified lease did not authorize the active binding")
        return decision

    def activate(self, product: Manifest, license_key: str,
                 verifier: LeaseVerifier,
                 repository: VerifiedLicenseRepository) -> AuthorizationDecision:
        """Normal production activation; no legacy fallback is permitted."""
        return self.activate_platform_lease(product, license_key, verifier, repository)

    def activate_legacy(self, product: Manifest, device_name: str | None = None) -> ActivationState:
        """Deprecated compatibility orchestration; never used for platform v2 activation."""
        if not product.is_validated:
            raise ManifestProvenanceError("Activation requires a manifest validated by the manifest pipeline")
        self.sessions.current_session()
        generation = self.sessions.generation
        installation_id = self.identity.load_or_create()
        identity_generation = getattr(self.identity, "generation", 0)
        device_key = self.fingerprint.calculate()
        key = (product.productId, device_key, generation)
        operation_key = (product.productId, device_key)
        with self._condition:
            flight = self._flights.get(key)
            if flight is None:
                operation_version = self._operation_versions.get(operation_key, 0) + 1
                self._operation_versions[operation_key] = operation_version
                flight = _ActivationFlight(threading.Event())
                self._flights[key] = flight
                owner = True
            else:
                owner = False
                operation_version = self._operation_versions[operation_key]
        if not owner:
            flight.event.wait()
            if flight.error: raise flight.error
            if flight.result is None: raise RuntimeError("Activation completed without a result")
            return flight.result
        try:
            result = self._activate_remote(product, device_name, installation_id, device_key, generation, identity_generation, operation_key, operation_version)
            flight.result = result
        except Exception as exc:
            flight.error = exc
        finally:
            with self._condition:
                self._flights.pop(key, None)
                flight.event.set()
        if flight.error: raise flight.error
        if flight.result is None: raise RuntimeError("Activation completed without a result")
        return flight.result

    def _activate_remote(self, product: Manifest, device_name: str | None,
                         installation_id: str, device_key: str, generation: int,
                         identity_generation: int, operation_key: tuple[str, str], operation_version: int) -> ActivationState:
        token = self.sessions.access_token()
        metadata = DeviceMetadata(installation_id=installation_id, device_fingerprint=device_key,
            fingerprint_schema_version=FINGERPRINT_SCHEMA_VERSION,
            operating_system=self.fingerprint.signals["platform"],
            os_version=self.fingerprint.signals["os_version"],
            architecture=self.fingerprint.signals["architecture"],
            device_name=device_name, agent_version=self.agent_version)
        device = self.client.register_typed_device(DeviceRegistrationRequest(metadata=metadata), token)
        self._require_current(generation, identity_generation, operation_key, operation_version)
        if device.status == "denied": raise DeviceRegistrationError("The device was not authorized")
        entitlement = self.client.entitlement(product.productId, token)
        self._require_current(generation, identity_generation, operation_key, operation_version)
        self._require_eligible(entitlement.status)
        activation = self.client.activate(ActivationRequest(product_id=product.productId,
            license_id=entitlement.license_id, device_id=device.device_id,
            installed_version=product.version), token)
        self._require_current(generation, identity_generation, operation_key, operation_version)
        try:
            self._audit("activation_attempted", activation.status, product.productId,
                        device.device_id, activation.activation_id)
        except Exception as exc:
            raise ActivationPartialFailureError(
                "Remote activation succeeded but audit persistence failed"
            ) from exc
        self._require_eligible(activation.status)
        verification = self.client.verify_activation(ActivationVerificationRequest(
            activation_id=activation.activation_id, product_id=product.productId,
            device_id=device.device_id), token)
        self._require_current(generation, identity_generation, operation_key, operation_version)
        if not self._valid_verification(verification, activation.activation_id,
                                        product.productId, device.device_id):
            raise ActivationVerificationError("Malformed activation verification response")
        if not verification.valid or verification.status != "active":
            self._require_eligible(verification.status)
            raise ActivationDeniedError("Activation verification did not authorize activation")
        try:
            if self.cache:
                self.cache.save_activation(product.productId, activation.license_id,
                    device.device_id, activation.activation_id, verification.status)
                self._audit("activation_succeeded", "active", product.productId,
                    device.device_id, activation.activation_id)
        except Exception as exc:
            raise ActivationPartialFailureError("Remote activation succeeded but local reconciliation failed") from exc
        return ActivationState(state="active", activation_id=verification.activation_id)

    def verify(self, product: Manifest, activation_id: str, device_id: str) -> ActivationState:
        if not product.is_validated:
            raise ManifestProvenanceError("Verification requires a validated manifest")
        self.sessions.current_session()
        generation = self.sessions.generation
        response = self.client.verify_activation(ActivationVerificationRequest(
            activation_id=activation_id, product_id=product.productId, device_id=device_id),
            self.sessions.access_token())
        self._require_current(generation)
        if not self._valid_verification(response, activation_id, product.productId, device_id):
            raise ActivationVerificationError("Malformed activation verification response")
        state = response.status if response.valid else response.status
        if self.cache:
            if state == "active" and response.valid:
                self.cache.update_activation_status(product.productId, device_id, state)
            else:
                self.cache.invalidate_activation(product.productId, device_id, state)
        if not response.valid or state != "active": self._require_eligible(state)
        return ActivationState(state=state, activation_id=response.activation_id)

    def deactivate(self, product: Manifest, activation_id: str, device_id: str) -> bool:
        if not product.is_validated:
            raise ManifestProvenanceError("Deactivation requires a validated manifest")
        self.sessions.current_session()
        generation = self.sessions.generation
        operation_key = (product.productId, self.fingerprint.calculate())
        with self._condition:
            operation_version = self._operation_versions.get(operation_key, 0) + 1
            self._operation_versions[operation_key] = operation_version
        response = self.client.deactivate(DeactivationRequest(activation_id=activation_id, device_id=device_id), self.sessions.access_token())
        self._require_current(generation, getattr(self.identity, "generation", 0), operation_key, operation_version)
        if not response.success: return False
        if self.cache:
            try:
                self.cache.invalidate_activation(product.productId, device_id, "inactive")
                self._audit("device_deactivated", "success", product.productId, device_id, activation_id)
            except Exception as exc:
                raise DeactivationPartialFailureError("Remote deactivation succeeded but local reconciliation failed") from exc
        return True

    def _require_current(self, generation: int, identity_generation: int | None = None,
                         operation_key: tuple[str, str] | None = None,
                         operation_version: int | None = None) -> None:
        if not self.sessions.is_generation_current(generation):
            raise MissingSessionError("Session changed during licensing operation")
        if identity_generation is not None and getattr(self.identity, "generation", 0) != identity_generation:
            raise MissingSessionError("Installation identity changed during licensing operation")
        if operation_key is not None:
            with self._condition:
                if self._operation_versions.get(operation_key) != operation_version:
                    raise MissingSessionError("A newer licensing operation superseded this operation")

    def _audit(self, event_type: str, result: str, product_id: str, device_id: str, activation_id: str) -> None:
        sink = self.audit or self.cache
        if sink:
            sink.record_audit_event(event_type, result, product_id, device_id, activation_id)

    @staticmethod
    def _valid_verification(response: Any, activation_id: str, product_id: str,
                            device_id: str) -> bool:
        return (isinstance(getattr(response, "valid", None), bool)
                and getattr(response, "status", None) in {"active", "expired", "suspended", "revoked", "unknown"}
                and getattr(response, "activation_id", None) == activation_id
                and getattr(response, "product_id", product_id) == product_id
                and getattr(response, "device_id", device_id) == device_id)

    @staticmethod
    def _require_eligible(status: str) -> None:
        if status in {"active", "pending"}: return
        mapping = {"expired": LicenseExpiredError, "suspended": LicenseSuspendedError,
            "revoked": LicenseRevokedError, "device_limit_reached": DeviceLimitReachedError,
            "product_unavailable": ProductNotEntitledError,
            "version_not_entitled": ProductNotEntitledError,
            "inactive": NoLicenseAvailableError}
        raise mapping.get(status, UnknownLicenseStateError)("The licensing platform did not authorize this operation")
