"""Offline authorization decisions based on verified signed leases."""

from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Callable

from packaging.version import InvalidVersion, Version

from ..manifest.models import Manifest
from .lease import LicenseLease, LeaseMetadata, LeaseMetadataStore


class AuthorizationState(StrEnum):
    AUTHORIZED = "authorized"
    LEASE_EXPIRED = "lease_expired"
    LEASE_NOT_YET_VALID = "lease_not_yet_valid"
    LEASE_REVOKED = "lease_revoked"
    LEASE_SUPERSEDED = "lease_superseded"
    LEASE_WRONG_PRODUCT = "lease_wrong_product"
    LEASE_WRONG_DEVICE = "lease_wrong_device"
    LEASE_WRONG_INSTALLATION = "lease_wrong_installation"
    LEASE_VERSION_REJECTED = "lease_version_rejected"
    AUTHORIZATION_DENIED = "authorization_denied"


class AuthorizationDecision:
    def __init__(self, state: AuthorizationState, reason: str = ""):
        self.state, self.reason = state, reason

    @property
    def authorized(self) -> bool:
        return self.state is AuthorizationState.AUTHORIZED


class AuthorizationService:
    def __init__(self, store: LeaseMetadataStore | None = None,
                 clock: Callable[[], datetime] | None = None,
                 skew: timedelta = timedelta(seconds=30)):
        self.store, self.clock, self.skew = store, clock or (lambda: datetime.now(timezone.utc)), skew

    def authorize(self, manifest: Manifest, lease: LicenseLease,
                  installation_id: str, device_id: str,
                  version: str | None = None) -> AuthorizationDecision:
        now = self.clock()
        if now.tzinfo is None:
            return AuthorizationDecision(AuthorizationState.AUTHORIZATION_DENIED, "Clock must be timezone-aware")
        if lease.product_id != manifest.productId:
            return AuthorizationDecision(AuthorizationState.LEASE_WRONG_PRODUCT)
        if lease.installation_id != installation_id:
            return AuthorizationDecision(AuthorizationState.LEASE_WRONG_INSTALLATION)
        if lease.device_id != device_id:
            return AuthorizationDecision(AuthorizationState.LEASE_WRONG_DEVICE)
        if now + self.skew < lease.not_before:
            return AuthorizationDecision(AuthorizationState.LEASE_NOT_YET_VALID)
        if now - self.skew >= lease.expires_at:
            return AuthorizationDecision(AuthorizationState.LEASE_EXPIRED)
        requested = version or manifest.version
        try:
            if Version(requested) != Version(lease.version):
                return AuthorizationDecision(AuthorizationState.LEASE_VERSION_REJECTED)
        except InvalidVersion:
            return AuthorizationDecision(AuthorizationState.LEASE_VERSION_REJECTED)
        if self.store:
            self.store.save(LeaseMetadata(lease_id=lease.lease_id,
                product_id=lease.product_id, installation_id=lease.installation_id,
                device_id=lease.device_id, generation=lease.generation,
                status="verified", issued_at=lease.issued_at,
                expires_at=lease.expires_at, issuer=lease.issuer,
                key_id=lease.key_id, verified_at=now))
        return AuthorizationDecision(AuthorizationState.AUTHORIZED)
