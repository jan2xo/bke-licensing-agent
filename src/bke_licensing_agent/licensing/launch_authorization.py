"""Product-agnostic launch authorization decisions; never executes products."""

import hashlib
import json
import threading
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any, Callable

from ..manifest.models import Manifest
from .lease import (
    LicenseLease,
    LeaseInvalidSignatureError,
    LeaseMalformedError,
    LeaseRevokedError,
    LeaseSupersededError,
    LeaseUnknownKeyError,
    LeaseUnsupportedAlgorithmError,
    LeaseVerifier,
)


class AuthorizationReason(StrEnum):
    AUTHORIZED_ONLINE = "authorized_online"
    AUTHORIZED_OFFLINE = "authorized_offline"
    MISSING_LEASE = "missing_lease"
    INVALID_SIGNATURE = "invalid_signature"
    UNKNOWN_SIGNING_KEY = "unknown_signing_key"
    MALFORMED_LEASE = "malformed_lease"
    LEASE_NOT_YET_VALID = "lease_not_yet_valid"
    LEASE_EXPIRED = "lease_expired"
    LEASE_REVOKED = "lease_revoked"
    LEASE_SUPERSEDED = "lease_superseded"
    LEASE_REPLAYED = "lease_replayed"
    STALE_LEASE = "stale_lease"
    WRONG_PRODUCT = "wrong_product"
    WRONG_INSTALLATION = "wrong_installation"
    WRONG_DEVICE = "wrong_device"
    UNSUPPORTED_VERSION = "unsupported_version"
    CLOCK_ROLLBACK_DETECTED = "clock_rollback_detected"
    TRUSTED_TIME_UNAVAILABLE = "trusted_time_unavailable"
    IDENTITY_CHANGED = "identity_changed"
    STALE_OPERATION = "stale_operation"
    AUTHORIZATION_DENIED = "authorization_denied"
    AUDIT_FAILED = "audit_failed"


@dataclass(frozen=True)
class AuthorizationDecision:
    allowed: bool
    reason: AuthorizationReason
    product_id: str
    lease_id: str | None = None
    lease_generation: int | None = None
    server_revision: int | None = None
    authorized_at: datetime | None = None
    expires_at: datetime | None = None
    offline: bool = True
    correlation_id: str | None = None
    installation_id: str | None = None
    installation_generation: int | None = None
    device_id: str | None = None
    product_version: str | None = None


@dataclass
class _AuthorizationFlight:
    event: threading.Event
    result: AuthorizationDecision | None = None
    error: BaseException | None = None


class LaunchAuthorizationService:
    def __init__(self, verifier: LeaseVerifier, repository: Any,
                 clock: Callable[[], datetime], audit: Any | None = None,
                 skew: timedelta = timedelta(seconds=30)):
        self.verifier, self.repository, self.clock = verifier, repository, clock
        self.audit, self.skew = audit, skew
        self._last_trusted_time: datetime | None = None
        self._condition = threading.Condition()
        self._flights: dict[str, _AuthorizationFlight] = {}

    def observe_trusted_time(self, server_time: datetime) -> None:
        if server_time.tzinfo is None:
            raise ValueError("Trusted server time must be timezone-aware")
        if self._last_trusted_time is not None and server_time < self._last_trusted_time:
            raise ValueError("Trusted server time moved backward")
        self._last_trusted_time = server_time

    def authorize(self, manifest: Manifest, installation: Any,
                  device_id: str, signed_lease: dict[str, Any] | str | None,
                  version: str | None = None, online: bool = False,
                  session_generation: int | None = None) -> AuthorizationDecision:
        product_id = getattr(manifest, "productId", "")
        if not isinstance(product_id, str) or not product_id:
            return self._finish(self._denied("", AuthorizationReason.AUTHORIZATION_DENIED))
        operation_generation = session_generation
        if operation_generation is None:
            operation_generation = getattr(installation, "session_generation", None)
        identity_generation = getattr(installation, "generation", 0)
        key = self._flight_key(product_id, device_id, operation_generation,
                               identity_generation, signed_lease, version, online)
        with self._condition:
            flight = self._flights.get(key)
            if flight is None:
                flight = _AuthorizationFlight(threading.Event())
                self._flights[key] = flight
                owner = True
            else:
                owner = False
        if not owner:
            flight.event.wait()
            if flight.error is not None:
                raise flight.error
            if flight.result is None:
                raise RuntimeError("Authorization completed without a result")
            return flight.result
        try:
            flight.result = self._authorize_once(
                manifest, installation, device_id, signed_lease, version, online,
                operation_generation, identity_generation,
            )
        except BaseException as exc:
            flight.error = exc
        finally:
            with self._condition:
                self._flights.pop(key, None)
                flight.event.set()
        if flight.error is not None:
            raise flight.error
        if flight.result is None:
            raise RuntimeError("Authorization completed without a result")
        return flight.result

    def _authorize_once(self, manifest, installation, device_id, signed_lease,
                        version, online, operation_generation, identity_generation):
        product_id = manifest.productId
        if not getattr(manifest, "is_validated", False):
            return self._finish(self._denied(product_id, AuthorizationReason.AUTHORIZATION_DENIED))
        if signed_lease is None:
            return self._bind(self._finish(self._denied(product_id, AuthorizationReason.MISSING_LEASE)),
                None, device_id, manifest.version, identity_generation)
        identity = installation.load_or_create()
        def bind(result, lease=None):
            return self._bind(result, identity, device_id, manifest.version, identity_generation)
        try:
            lease = self.verifier.verify(signed_lease)
        except LeaseUnknownKeyError:
            return bind(self._finish(self._denied(product_id, AuthorizationReason.UNKNOWN_SIGNING_KEY)))
        except LeaseInvalidSignatureError:
            return bind(self._finish(self._denied(product_id, AuthorizationReason.INVALID_SIGNATURE)))
        except LeaseRevokedError:
            return bind(self._finish(self._denied(product_id, AuthorizationReason.LEASE_REVOKED)))
        except LeaseSupersededError:
            return bind(self._finish(self._denied(product_id, AuthorizationReason.LEASE_SUPERSEDED)))
        except (LeaseMalformedError, LeaseUnsupportedAlgorithmError):
            return bind(self._finish(self._denied(product_id, AuthorizationReason.MALFORMED_LEASE)))
        if not self._operation_current(installation, operation_generation, identity_generation):
            return self._finish(self._denied(product_id, AuthorizationReason.STALE_OPERATION, lease))
        result = self._authorize_verified(manifest, installation, identity, identity_generation,
            device_id, lease, version, online, operation_generation)
        return replace(result, installation_id=identity,
            installation_generation=identity_generation, device_id=device_id,
            product_version=manifest.version)

    @staticmethod
    def _bind(result, installation_id, device_id, product_version, installation_generation):
        return replace(result, installation_id=installation_id,
            installation_generation=installation_generation, device_id=device_id,
            product_version=product_version)

    def _authorize_verified(self, manifest, installation, identity, identity_generation,
                            device_id, lease: LicenseLease, version, online, session_generation):
        product_id = manifest.productId
        if lease.product_id != product_id:
            return self._finish(self._denied(product_id, AuthorizationReason.WRONG_PRODUCT, lease))
        if lease.installation_id != identity:
            return self._finish(self._denied(product_id, AuthorizationReason.WRONG_INSTALLATION, lease))
        if lease.device_id != device_id:
            return self._finish(self._denied(product_id, AuthorizationReason.WRONG_DEVICE, lease))
        requested = version or manifest.version
        if requested != lease.version:
            return self._finish(self._denied(product_id, AuthorizationReason.UNSUPPORTED_VERSION, lease))
        now = self.clock()
        if now.tzinfo is None or self._last_trusted_time is None:
            return self._finish(self._denied(product_id, AuthorizationReason.TRUSTED_TIME_UNAVAILABLE, lease))
        if now < self._last_trusted_time - self.skew:
            return self._finish(self._denied(product_id, AuthorizationReason.CLOCK_ROLLBACK_DETECTED, lease))
        if now + self.skew < lease.not_before:
            return self._finish(self._denied(product_id, AuthorizationReason.LEASE_NOT_YET_VALID, lease))
        if now - self.skew >= lease.expires_at:
            return self._finish(self._denied(product_id, AuthorizationReason.LEASE_EXPIRED, lease))
        current = self.repository.latest(product_id, device_id)
        if current is not None and current.status == "revoked":
            return self._finish(self._denied(product_id, AuthorizationReason.LEASE_REVOKED, lease))
        if current is not None and current.status == "superseded":
            return self._finish(self._denied(product_id, AuthorizationReason.LEASE_SUPERSEDED, lease))
        if current is not None and (lease.generation < current.generation or
                                    lease.server_revision < current.server_revision):
            return self._finish(self._denied(product_id, AuthorizationReason.STALE_LEASE, lease))
        if getattr(installation, "generation", 0) != identity_generation:
            return self._finish(self._denied(product_id, AuthorizationReason.IDENTITY_CHANGED, lease))
        if session_generation is not None and not getattr(installation, "session_current", lambda _: True)(session_generation):
            return self._finish(self._denied(product_id, AuthorizationReason.STALE_OPERATION, lease))
        reason = AuthorizationReason.AUTHORIZED_ONLINE if online else AuthorizationReason.AUTHORIZED_OFFLINE
        return self._finish(AuthorizationDecision(True, reason, product_id, lease.lease_id,
            lease.generation, lease.server_revision, now, lease.expires_at, not online))

    @staticmethod
    def _flight_key(product_id, device_id, session_generation, identity_generation,
                    signed_lease, version, online) -> str:
        try:
            serialized = json.dumps(signed_lease, sort_keys=True, separators=(",", ":"), default=str)
        except (TypeError, ValueError):
            serialized = repr(signed_lease)
        material = repr((product_id, device_id, session_generation,
                         identity_generation, version, online, serialized)).encode()
        return hashlib.sha256(material).hexdigest()

    @staticmethod
    def _operation_current(installation, session_generation, identity_generation) -> bool:
        if getattr(installation, "generation", 0) != identity_generation:
            return False
        if session_generation is not None:
            return getattr(installation, "session_current", lambda _: True)(session_generation)
        return True

    def _finish(self, decision: AuthorizationDecision) -> AuthorizationDecision:
        if self.audit:
            try:
                self.audit.record_audit_event("authorization", decision.reason.value,
                    product_id=decision.product_id, activation_id=decision.lease_id)
            except Exception:
                return AuthorizationDecision(False, AuthorizationReason.AUDIT_FAILED,
                    decision.product_id, decision.lease_id, decision.lease_generation,
                    decision.server_revision, decision.authorized_at, decision.expires_at,
                    decision.offline, decision.correlation_id)
        return decision

    @staticmethod
    def _denied(product_id, reason, lease=None):
        return AuthorizationDecision(False, reason, product_id,
            getattr(lease, "lease_id", None), getattr(lease, "generation", None),
            getattr(lease, "server_revision", None), expires_at=getattr(lease, "expires_at", None))
