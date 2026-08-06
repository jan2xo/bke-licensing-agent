"""Deterministic certification-only platform boundary."""

from dataclasses import dataclass
import base64
from datetime import datetime, timedelta, timezone
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from bke_licensing_agent.licensing.lease import LicenseLease
from enum import StrEnum


class MockActivationState(StrEnum):
    AUTHORIZED = "authorized"
    DENIED = "denied"
    UNAVAILABLE = "unavailable"
    ACTIVATION_REQUIRED = "activation_required"


@dataclass(frozen=True)
class MockActivationResponse:
    state: MockActivationState
    reason: str = ""
    signed_lease: dict[str, str] | None = None


class MockBKEPlatform:
    SCENARIOS = {
        "BKE-DEMO-VALID": MockActivationState.AUTHORIZED,
        "BKE-DEMO-LICENSE-1": MockActivationState.AUTHORIZED,
        "BKE-DEMO-LICENSE-2": MockActivationState.AUTHORIZED,
        "BKE-DEMO-BASIC": MockActivationState.AUTHORIZED,
        "BKE-DEMO-PRO": MockActivationState.AUTHORIZED,
        "BKE-DEMO-ENTERPRISE": MockActivationState.AUTHORIZED,
        "CERT-LICENSE-A": MockActivationState.AUTHORIZED,
        "CERT-LICENSE-B": MockActivationState.AUTHORIZED,
        "CERT-LICENSE-C": MockActivationState.AUTHORIZED,
        "CERT-LICENSE-BAD-SIGNATURE": MockActivationState.DENIED,
        "BKE-DEMO-INVALID": MockActivationState.DENIED,
        "BKE-DEMO-EXPIRED": MockActivationState.DENIED,
        "BKE-DEMO-REVOKED": MockActivationState.DENIED,
        "BKE-DEMO-SUSPENDED": MockActivationState.DENIED,
        "BKE-DEMO-DEVICE-LIMIT": MockActivationState.DENIED,
        "BKE-DEMO-WRONG-PRODUCT": MockActivationState.DENIED,
        "BKE-DEMO-WRONG-DEVICE": MockActivationState.DENIED,
        "BKE-DEMO-MALFORMED": MockActivationState.DENIED,
        "BKE-DEMO-INVALID-SIGNATURE": MockActivationState.DENIED,
        "BKE-DEMO-UNKNOWN-KEY": MockActivationState.DENIED,
    }

    TEST_PRIVATE_KEY = bytes(range(1, 33))

    @classmethod
    def trusted_public_key(cls) -> str:
        key = Ed25519PrivateKey.from_private_bytes(cls.TEST_PRIVATE_KEY)
        return key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    @classmethod
    def signed_lease(cls, *, product_id="bke-demo-product", device_id="demo-device",
                     expires_at=None, revoked=False, suspended=False,
                     lease_id="demo-lease-1", generation=1) -> dict[str, str]:
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        lease = LicenseLease(lease_id=lease_id, generation=generation, server_revision=generation,
            product_id=product_id, installation_id="demo-installation",
            device_id=device_id, version="1.0.0", issuer="BKE certification platform",
            issued_at=now, not_before=now - timedelta(minutes=1),
            expires_at=expires_at or now + timedelta(hours=1), key_id="certification-test",
            algorithm="Ed25519", revoked=revoked, superseded_by=None)
        payload = lease.model_dump_json()
        if suspended:
            payload = json.dumps({**json.loads(payload), "status": "suspended"}, sort_keys=True)
        key = Ed25519PrivateKey.from_private_bytes(cls.TEST_PRIVATE_KEY)
        signature = key.sign(payload.encode())
        return {"payload": payload, "signature": base64.b64encode(signature).decode(),
                "key_id": "certification-test", "algorithm": "Ed25519"}

    def activate(self, license_key: str, product_id: str = "bke-demo-product") -> MockActivationResponse:
        state = self.SCENARIOS.get(license_key)
        if state is None:
            return MockActivationResponse(MockActivationState.DENIED, "unknown_license_key")
        if state is MockActivationState.AUTHORIZED and product_id == "bke-demo-product":
            editions = {"BKE-DEMO-PRO": ("demo-lease-pro", 2),
                        "BKE-DEMO-ENTERPRISE": ("demo-lease-enterprise", 3),
                        "BKE-DEMO-LICENSE-2": ("demo-lease-2", 2),
                        "CERT-LICENSE-A": ("cert-license-a", 1),
                        "CERT-LICENSE-B": ("cert-license-b", 2),
                        "CERT-LICENSE-C": ("cert-license-c", 3)}
            lease_id, generation = editions.get(license_key, ("demo-lease-basic", 1))
            return MockActivationResponse(state, "verified_test_lease", self.signed_lease(lease_id=lease_id, generation=generation))
        if state is MockActivationState.AUTHORIZED:
            return MockActivationResponse(MockActivationState.DENIED, "wrong_product")
        return MockActivationResponse(state, license_key.lower().replace("bke-demo-", ""))

    def retrieve_lease(self, product_id: str = "bke-demo-product", lease_id: str | None = None,
                       generation: int = 1) -> dict[str, str] | None:
        """Return the current certification lease through the platform boundary."""
        if product_id != "bke-demo-product":
            return None
        return self.signed_lease(product_id=product_id, lease_id=lease_id or "demo-lease-basic", generation=generation)
