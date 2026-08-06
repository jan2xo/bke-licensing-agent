from datetime import datetime, timezone

from bke_licensing_agent.licensing.license_repository import (
    ActiveLicenseBinding,
    VerifiedLicenseRecord,
    VerifiedLicenseRepository,
)
from bke_licensing_agent.storage.database import Database
from bke_licensing_agent.licensing.authorization import AuthorizationService, AuthorizationState
from bke_licensing_agent.manifest.validator import validate_manifest
from bke_licensing_agent.licensing.lease import LicenseLease


def record(license_id="license-a"):
    moment = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return VerifiedLicenseRecord(
        license_id=license_id, product_id="bke-demo-product", product_version="1.0.0",
        installation_id="install", device_id="device", lease_id=f"lease-{license_id}",
        generation=1, server_revision=1, issued_at=moment, not_before=moment,
        expires_at=moment.replace(year=2027), status="verified", key_id="key",
        created_at=moment, updated_at=moment,
    )


def test_repository_stores_many_licenses_and_one_active_binding(tmp_path):
    with Database(tmp_path / "agent.db") as db:
        repository = VerifiedLicenseRepository(db)
        repository.save(record("license-a"))
        repository.save(record("license-b"))
        repository.bind(ActiveLicenseBinding(
            product_id="bke-demo-product", installation_id="install", device_id="device",
            active_license_id="license-b", active_lease_id="lease-license-b",
            generation=1, server_revision=1, binding_version=1,
            updated_at=datetime.now(timezone.utc),
        ))
        assert {item.license_id for item in repository.list_for_product("bke-demo-product")} == {"license-a", "license-b"}
        assert repository.active("bke-demo-product", "install", "device").active_license_id == "license-b"


def test_binding_cannot_reference_missing_license(tmp_path):
    with Database(tmp_path / "agent.db") as db:
        repository = VerifiedLicenseRepository(db)
        try:
            repository.bind(ActiveLicenseBinding(
                product_id="bke-demo-product", installation_id="install", device_id="device",
                active_license_id="missing", active_lease_id="lease",
                generation=1, server_revision=1, binding_version=1,
                updated_at=datetime.now(timezone.utc),
            ))
        except Exception as exc:
            assert "missing license" in str(exc)
        else:
            raise AssertionError("missing license binding was accepted")


def test_authorization_uses_only_the_active_binding(tmp_path):
    with Database(tmp_path / "agent.db") as db:
        repository = VerifiedLicenseRepository(db)
        stored = record("license-a")
        repository.save(stored)
        repository.bind(ActiveLicenseBinding(
            product_id="bke-demo-product", installation_id="install", device_id="device",
            active_license_id="license-a", active_lease_id=stored.lease_id,
            generation=1, server_revision=1, binding_version=1,
            updated_at=datetime.now(timezone.utc),
        ))
        lease = LicenseLease(
            lease_id=stored.lease_id, generation=1, server_revision=1,
            product_id="bke-demo-product", installation_id="install", device_id="device",
            version="1.0.0", issuer="test", issued_at=stored.issued_at,
            not_before=stored.not_before, expires_at=stored.expires_at,
            key_id="key", algorithm="test",
        )
        manifest = validate_manifest({
            "schemaVersion": 1, "productId": "bke-demo-product", "displayName": "Demo",
            "version": "1.0.0", "entryPoint": "demo.py", "updateChannel": "stable",
            "minimumAgentVersion": "1.0.0", "platform": "linux", "architecture": "x64",
        })
        decision = AuthorizationService(clock=lambda: lease.issued_at).authorize_from_active_binding(
            manifest, "install", "device", repository, lambda lease_id: lease if lease_id == lease.lease_id else None)
        assert decision.state is AuthorizationState.AUTHORIZED
