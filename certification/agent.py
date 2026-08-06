"""Certification adapter composing mock platform with production verification."""

from bke_licensing_agent.licensing.authorization import AuthorizationService
from bke_licensing_agent.licensing.lease import LeaseVerificationError, LeaseVerifier
from bke_licensing_agent.licensing.lease_storage import LeaseMetadataRepository
from bke_licensing_agent.licensing.license_repository import (
    ActiveLicenseBinding, VerifiedLicenseRecord, VerifiedLicenseRepository,
)
from bke_licensing_agent.storage.database import Database

from .mock_platform import MockActivationState, MockBKEPlatform


class CertificationAgent:
    def __init__(self, platform=None, license_key: str | None = None,
                 installation_id: str = "demo-installation", device_id: str = "demo-device",
                 database: Database | None = None):
        self.platform = platform or MockBKEPlatform()
        self.license_key = license_key
        self.installation_id, self.device_id = installation_id, device_id
        self.lease = None
        self.database = database or Database()
        self.metadata = LeaseMetadataRepository(self.database)
        self.licenses = VerifiedLicenseRepository(self.database)

    def connect(self): pass
    def login(self, credentials): self.license_key = credentials
    def login_with_license_key(self, key): self.license_key = key
    def discovered_products(self): return ["bke-demo-product"]

    def activate(self, product):
        response = self.platform.activate(self.license_key or "", product_id=product.productId if hasattr(product, "productId") else product)
        if response.state is not MockActivationState.AUTHORIZED or response.signed_lease is None:
            raise RuntimeError(response.reason or response.state.value)
        verifier = LeaseVerifier({"certification-test": self.platform.trusted_public_key()})
        candidate = verifier.verify(response.signed_lease)
        previous_binding = self.licenses.active(product.productId, self.installation_id, self.device_id)
        try:
            preflight = AuthorizationService(clock=lambda: candidate.issued_at).authorize(
                product, candidate, self.installation_id, self.device_id)
            if not preflight.authorized:
                raise RuntimeError(preflight.reason or preflight.state.value)
            now = candidate.issued_at
            self.licenses.save(VerifiedLicenseRecord(
                license_id=candidate.lease_id, product_id=candidate.product_id,
                product_version=candidate.version, installation_id=candidate.installation_id,
                device_id=candidate.device_id, lease_id=candidate.lease_id,
                generation=candidate.generation, server_revision=candidate.server_revision,
                issued_at=candidate.issued_at, not_before=candidate.not_before,
                expires_at=candidate.expires_at, status="verified", key_id=candidate.key_id,
                created_at=now, updated_at=now,
            ))
            binding_version = previous_binding.binding_version + 1 if previous_binding else 1
            self.licenses.bind(ActiveLicenseBinding(
                product_id=candidate.product_id, installation_id=candidate.installation_id,
                device_id=candidate.device_id, active_license_id=candidate.lease_id,
                active_lease_id=candidate.lease_id, generation=candidate.generation,
                server_revision=candidate.server_revision, binding_version=binding_version,
                updated_at=now,
            ))
            result = AuthorizationService(clock=lambda: candidate.issued_at).authorize_from_active_binding(
                product, self.installation_id, self.device_id, self.licenses,
                lambda lease_id: candidate if lease_id == candidate.lease_id else None)
        except Exception:
            self.licenses.database.connection.execute("DELETE FROM verified_licenses WHERE license_id=?", (candidate.lease_id,))
            if previous_binding is not None:
                self.licenses.bind(previous_binding)
            raise
        if not result.authorized:
            self.licenses.database.connection.execute("DELETE FROM verified_licenses WHERE license_id=?", (candidate.lease_id,))
            if previous_binding is not None:
                self.licenses.bind(previous_binding)
            raise RuntimeError(result.reason or result.state.value)
        self.lease = candidate
        apply_certification_entitlements(result, candidate.lease_id)
        return result

    def activate_license(self, product):
        """Replace the active lease only after candidate verification succeeds."""
        previous = self.lease
        try:
            return self.activate(product)
        except Exception:
            self.lease = previous
            raise

    def authorize(self, product):
        binding = self.licenses.active(product.productId, self.installation_id, self.device_id)
        if binding is None:
            raise RuntimeError("activation_required")
        raw_lease = self.platform.retrieve_lease(product.productId, binding.active_lease_id, binding.generation)
        if raw_lease is None:
            raise RuntimeError("authorization_unavailable")
        verifier = LeaseVerifier({"certification-test": self.platform.trusted_public_key()})
        try:
            current = verifier.verify(raw_lease)
        except LeaseVerificationError as exc:
            raise RuntimeError("activation_required") from exc
        result = AuthorizationService(clock=lambda: current.issued_at).authorize_from_active_binding(
            product, self.installation_id, self.device_id, self.licenses,
            lambda lease_id: current if lease_id == current.lease_id else None)
        if not result.authorized:
            raise RuntimeError("activation_required")
        self.lease = current
        apply_certification_entitlements(result, current.lease_id)
        return result

    def list_licenses(self, product):
        binding = self.licenses.active(product.productId, self.installation_id, self.device_id)
        return [{"license_id": item.license_id[-6:], "status": item.status,
                 "expires_at": item.expires_at.isoformat(),
                 "active": binding is not None and binding.active_license_id == item.license_id}
                for item in self.licenses.list_for_product(product.productId)]

    def select_license(self, product, license_id: str):
        target = self.licenses.load(license_id)
        if target is None or target.product_id != product.productId:
            raise RuntimeError("license_selection_denied")
        current = self.licenses.active(product.productId, self.installation_id, self.device_id)
        version = (current.binding_version + 1) if current else 1
        self.licenses.bind(ActiveLicenseBinding(
            product_id=target.product_id, installation_id=target.installation_id,
            device_id=target.device_id, active_license_id=target.license_id,
            active_lease_id=target.lease_id, generation=target.generation,
            server_revision=target.server_revision, binding_version=version,
            updated_at=target.updated_at,
        ))
        return self.authorize(product)

    def remove_license(self, product, license_id: str):
        binding = self.licenses.active(product.productId, self.installation_id, self.device_id)
        if binding is not None and binding.active_license_id == license_id:
            raise RuntimeError("active_license_cannot_be_removed")
        with self.database._lock, self.database.connection:
            self.database.connection.execute("DELETE FROM verified_licenses WHERE license_id=?", (license_id,))

    def add_license(self, product):
        previous = self.licenses.active(product.productId, self.installation_id, self.device_id)
        result = self.activate(product)
        if previous is not None:
            self.licenses.bind(previous)
            return self.authorize(product)
        return result

    def deactivate(self, product): self.lease = None
    def status(self, product): return self.authorize(product)
    def logout(self):
        if self.lease is not None:
            self.metadata.delete(self.lease.lease_id)
        self.lease = None

    def close(self):
        self.database.close()
    def return_to_requesting_product(self, product): pass


def apply_certification_entitlements(decision, license_key: str | None) -> None:
    entitlements = {
        "BKE-DEMO-BASIC": ("Basic", ("feature.basic",), {"projects": 1}),
        "BKE-DEMO-PRO": ("Professional", ("feature.basic", "feature.pro"), {"projects": 10}),
        "BKE-DEMO-ENTERPRISE": ("Enterprise", ("feature.basic", "feature.pro", "feature.enterprise"), {"projects": 100}),
        "CERT-LICENSE-A": ("Certification A", ("cert.feature.a",), {"cert.projects": 1}),
        "CERT-LICENSE-B": ("Certification B", ("cert.feature.a", "cert.feature.b"), {"cert.projects": 10}),
        "CERT-LICENSE-C": ("Certification C", ("cert.feature.a", "cert.feature.b", "cert.feature.c"), {"cert.projects": 100}),
    }.get(license_key or "")
    if entitlements is None and license_key:
        entitlements = {
            "demo-lease-basic": ("Basic", ("feature.basic",), {"projects": 1}),
            "demo-lease-pro": ("Professional", ("feature.basic", "feature.pro"), {"projects": 10}),
            "demo-lease-enterprise": ("Enterprise", ("feature.basic", "feature.pro", "feature.enterprise"), {"projects": 100}),
            "cert-license-a": ("Certification A", ("cert.feature.a",), {"cert.projects": 1}),
            "cert-license-b": ("Certification B", ("cert.feature.a", "cert.feature.b"), {"cert.projects": 10}),
            "cert-license-c": ("Certification C", ("cert.feature.a", "cert.feature.b", "cert.feature.c"), {"cert.projects": 100}),
        }.get(license_key)
    if entitlements:
        decision.edition, decision.features, decision.limits = entitlements
