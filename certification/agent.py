"""Certification adapter composing mock platform with production verification."""

from bke_licensing_agent.licensing.authorization import AuthorizationService
from bke_licensing_agent.licensing.lease import LeaseVerificationError, LeaseVerifier
from bke_licensing_agent.licensing.lease_storage import LeaseMetadataRepository
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

    def connect(self): pass
    def login(self, credentials): self.license_key = credentials
    def login_with_license_key(self, key): self.license_key = key
    def discovered_products(self): return ["bke-demo-product"]

    def activate(self, product):
        response = self.platform.activate(self.license_key or "", product_id=product.productId if hasattr(product, "productId") else product)
        if response.state is not MockActivationState.AUTHORIZED or response.signed_lease is None:
            raise RuntimeError(response.reason or response.state.value)
        verifier = LeaseVerifier({"certification-test": self.platform.trusted_public_key()})
        self.lease = verifier.verify(response.signed_lease)
        result = AuthorizationService(store=self.metadata, clock=lambda: self.lease.issued_at).authorize(
            product, self.lease, self.installation_id, self.device_id)
        if not result.authorized:
            raise RuntimeError(result.reason or result.state.value)
        return result

    def authorize(self, product):
        if self.lease is None:
            cached = self.metadata.latest(product.productId, self.device_id)
            if cached is None:
                raise RuntimeError("activation_required")
            raw_lease = self.platform.retrieve_lease(product.productId)
            if raw_lease is None:
                raise RuntimeError("authorization_unavailable")
            verifier = LeaseVerifier({"certification-test": self.platform.trusted_public_key()})
            try:
                self.lease = verifier.verify(raw_lease)
            except LeaseVerificationError as exc:
                self.metadata.delete(cached.lease_id)
                raise RuntimeError("activation_required") from exc
        result = AuthorizationService(store=self.metadata, clock=lambda: self.lease.issued_at).authorize(
            product, self.lease, self.installation_id, self.device_id)
        if not result.authorized:
            self.metadata.delete(self.lease.lease_id)
            raise RuntimeError("activation_required")
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
