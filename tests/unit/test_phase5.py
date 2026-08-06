from datetime import datetime, timedelta, timezone
import threading

import pytest

from bke_licensing_agent.api.config import ApiConfig
from bke_licensing_agent.auth.models import SessionInfo
from bke_licensing_agent.manifest.models import Manifest
from bke_licensing_agent.manifest.validator import validate_manifest
from bke_licensing_agent.devices.fingerprint import DeviceFingerprint, FINGERPRINT_SCHEMA_VERSION
from bke_licensing_agent.devices.identity import InstallationIdentity
from bke_licensing_agent.licensing.errors import (ActivationPartialFailureError,
    DeactivationPartialFailureError, LicenseExpiredError, UnknownLicenseStateError)
from bke_licensing_agent.licensing.errors import ActivationDeniedError, ActivationVerificationError
from bke_licensing_agent.auth.errors import MissingSessionError
from bke_licensing_agent.licensing.models import LicenseEntitlement, LicensePolicy
from bke_licensing_agent.licensing.service import LicensingService
from bke_licensing_agent.storage.database import Database


class Store:
    def __init__(self, value=None): self.value = value
    def save(self, account, value): self.value = value
    def load(self, account): return self.value
    def delete(self, account): self.value = None


def test_installation_identity_is_persistent_and_resettable():
    store = Store(); identity = InstallationIdentity(store)
    first = identity.load_or_create()
    assert identity.load_or_create() == first
    second = identity.reset()
    assert second != first


def test_corrupted_installation_identity_fails_closed():
    from bke_licensing_agent.auth.errors import CorruptedSecureStorageError
    with pytest.raises(CorruptedSecureStorageError): InstallationIdentity(Store({"installation_id": "bad"})).load_or_create()


def test_fingerprint_is_deterministic_versioned_and_hashed():
    fingerprint = DeviceFingerprint({"platform": " MacOS ", "architecture": "ARM64", "os_version": "1"})
    value = fingerprint.calculate()
    assert value == DeviceFingerprint({"os_version": "1", "architecture": "arm64", "platform": "macos"}).calculate()
    assert len(value) == 64
    assert FINGERPRINT_SCHEMA_VERSION not in value


def test_unknown_license_state_fails_closed():
    with pytest.raises(ValueError): LicenseEntitlement(license_id="l", product_id="p", status="mystery")


def test_license_status_mapping_fails_expired_and_unknown():
    with pytest.raises(LicenseExpiredError): LicensingService._require_eligible("expired")
    with pytest.raises(UnknownLicenseStateError): LicensingService._require_eligible("unknown")


def test_activation_cache_migration_stores_non_sensitive_metadata(tmp_path):
    db = Database(tmp_path / "agent.db")
    db.save_activation("product", "license", "device", "activation", "active")
    row = db.connection.execute("SELECT * FROM activation_cache").fetchone()
    assert dict(row)["activation_id"] == "activation"
    assert "access_token" not in dict(row)
    db.close()


def test_audit_events_are_persisted_without_sensitive_fields(tmp_path):
    db = Database(tmp_path / "agent.db")
    db.record_audit_event("activation_attempted", "active", product_id="p", device_id="d", activation_id="a")
    event = db.list_audit_events()[0]
    assert event["event_type"] == "activation_attempted"
    assert "access_token" not in event and "fingerprint" not in event
    db.close()


def test_activation_and_deactivation_use_shared_lock_and_cache(tmp_path):
    from bke_licensing_agent.licensing.models import ActivationResponse, DeviceRegistrationResponse

    class Sessions:
        generation = 1
        def current_session(self): return object()
        def access_token(self): return "token"
        def is_generation_current(self, generation): return generation == self.generation
    class Identity:
        def load_or_create(self): return "installation-id-123456789012345678901234567890"
    class Client:
        def register_typed_device(self, request, token): return DeviceRegistrationResponse(device_id="d", status="authorized")
        def entitlement(self, product_id, token): return LicenseEntitlement(license_id="l", product_id=product_id, status="active", policy=LicensePolicy(can_activate=True))
        def activate(self, request, token): return ActivationResponse(activation_id="a", license_id="l", product_id=request.product_id, device_id="d", status="active")
        def verify_activation(self, request, token): return type("R", (), {"valid": True, "status": "active", "activation_id": "a"})()
        def deactivate(self, request, token): return type("R", (), {"success": True})()
    class Fingerprint:
        signals = {"platform": "test", "os_version": "1", "architecture": "x64"}
        def calculate(self): return "f" * 64
    db = Database(tmp_path / "agent.db")
    service = LicensingService(Client(), Sessions(), Identity(), Fingerprint(), db)
    product = validate_manifest({"schemaVersion": 1, "productId": "p", "displayName": "P", "version": "1.0.0", "entryPoint": "app", "updateChannel": "stable", "minimumAgentVersion": "1.0.0", "platform": "linux", "architecture": "x64"})
    assert service.activate(product).state == "active"
    assert service.deactivate(product, "a", "d") is True
    assert {event["event_type"] for event in db.list_audit_events()} >= {"activation_attempted", "activation_succeeded", "device_deactivated"}
    db.close()


def test_manifest_provenance_is_required_for_activation():
    from bke_licensing_agent.licensing.errors import ManifestProvenanceError
    product = Manifest(schemaVersion=1, productId="p", displayName="P", version="1.0.0", entryPoint="app", updateChannel="stable", minimumAgentVersion="1.0.0", platform="linux", architecture="x64")
    with pytest.raises(ManifestProvenanceError): LicensingService(None, None, None, None).activate(product)


def test_migration_version_is_idempotent_and_upgradeable(tmp_path):
    db = Database(tmp_path / "agent.db")
    assert db.connection.execute("SELECT version FROM schema_version").fetchone()[0] == 5
    db.close()
    db = Database(tmp_path / "agent.db")
    assert db.connection.execute("SELECT version FROM schema_version").fetchone()[0] == 5
    db.close()


def test_newer_schema_is_rejected(tmp_path):
    db = Database(tmp_path / "agent.db"); db.close()
    import sqlite3
    connection = sqlite3.connect(tmp_path / "agent.db")
    connection.execute("UPDATE schema_version SET version=999"); connection.commit(); connection.close()
    with pytest.raises(RuntimeError, match="newer"):
        Database(tmp_path / "agent.db")


def test_migration_failure_rolls_back_and_later_startup_recovers(tmp_path):
    path = tmp_path / "agent.db"
    import sqlite3
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE schema_version (version INTEGER NOT NULL)")
    connection.execute("INSERT INTO schema_version VALUES (1)")
    connection.execute("CREATE TABLE discovered_products (product_id TEXT NOT NULL, display_name TEXT NOT NULL, version TEXT NOT NULL, manifest_path TEXT NOT NULL, product_root TEXT NOT NULL, entry_point_path TEXT NOT NULL, discovered_at TEXT NOT NULL, PRIMARY KEY (manifest_path))")
    connection.execute("CREATE TABLE activation_cache (product_id TEXT NOT NULL, license_id TEXT NOT NULL, device_id TEXT NOT NULL, activation_id TEXT NOT NULL, status TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY (product_id, device_id))")
    connection.commit(); connection.close()
    def fail_on_second_migration(version):
        if version == 2:
            raise RuntimeError("injected migration failure")
    with pytest.raises(RuntimeError, match="injected"):
        Database(path, migration_hook=fail_on_second_migration)
    connection = sqlite3.connect(path)
    assert connection.execute("SELECT version FROM schema_version").fetchone()[0] == 1
    assert connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_events'"
    ).fetchone() is None
    connection.close()
    with Database(path) as db:
        assert db.connection.execute("SELECT version FROM schema_version").fetchone()[0] == 5


def test_duplicate_activation_cache_upserts(tmp_path):
    db = Database(tmp_path / "agent.db")
    db.save_activation("p", "l1", "d", "a1", "active")
    db.save_activation("p", "l2", "d", "a2", "inactive")
    rows = db.connection.execute("SELECT * FROM activation_cache").fetchall()
    assert len(rows) == 1 and rows[0]["activation_id"] == "a2"
    db.close()


def _validated_product():
    return validate_manifest({"schemaVersion": 1, "productId": "p", "displayName": "P", "version": "1.0.0", "entryPoint": "app", "updateChannel": "stable", "minimumAgentVersion": "1.0.0", "platform": "linux", "architecture": "x64"})


class ActivationSession:
    generation = 1
    def current_session(self): return object()
    def access_token(self): return "token"
    def is_generation_current(self, generation): return generation == self.generation


class BlockingActivationClient:
    def __init__(self, verification_status="active", verification_valid=True, failure=None):
        from bke_licensing_agent.licensing.models import ActivationResponse, DeviceRegistrationResponse
        self.started = threading.Event(); self.release = threading.Event(); self.activation_calls = 0
        self.verification_status = verification_status; self.verification_valid = verification_valid; self.failure = failure
        self.ActivationResponse = ActivationResponse; self.DeviceRegistrationResponse = DeviceRegistrationResponse
    def register_typed_device(self, request, token): return self.DeviceRegistrationResponse(device_id="d", status="authorized")
    def entitlement(self, product_id, token): return LicenseEntitlement(license_id="l", product_id=product_id, status="active", policy=LicensePolicy(can_activate=True))
    def activate(self, request, token):
        self.activation_calls += 1; self.started.set(); self.release.wait(timeout=2)
        if self.failure: raise self.failure
        return self.ActivationResponse(activation_id="a", license_id="l", product_id="p", device_id="d", status="active")
    def verify_activation(self, request, token):
        return type("Verification", (), {"valid": self.verification_valid, "status": self.verification_status, "activation_id": "a"})()
    def deactivate(self, request, token): return type("Deactivation", (), {"success": True})()


@pytest.mark.parametrize("response", [
    object(),
    type("Malformed", (), {"valid": True, "status": "not-a-status", "activation_id": "a"})(),
    type("WrongActivation", (), {"valid": True, "status": "active", "activation_id": "other"})(),
    type("WrongProduct", (), {"valid": True, "status": "active", "activation_id": "a", "product_id": "other", "device_id": "d"})(),
    type("WrongDevice", (), {"valid": True, "status": "active", "activation_id": "a", "product_id": "p", "device_id": "other"})(),
])
def test_malformed_verification_responses_fail_closed(tmp_path, response):
    client = BlockingActivationClient(); client.verify_activation = lambda request, token: response
    service, db = _service_for_blocking(tmp_path, client)
    with pytest.raises(ActivationVerificationError): service.activate(_validated_product())
    assert db.connection.execute("SELECT COUNT(*) FROM activation_cache").fetchone()[0] == 0
    db.close()


def test_repeated_and_denied_deactivation_are_safe(tmp_path):
    client = BlockingActivationClient(); service, db = _service_for_blocking(tmp_path, client)
    service.cache = ThreadSafeCache()
    assert service.deactivate(_validated_product(), "a", "d") is True
    assert service.deactivate(_validated_product(), "a", "d") is True
    client.deactivate = lambda request, token: type("Denied", (), {"success": False})()
    assert service.deactivate(_validated_product(), "a", "d") is False
    assert sum(event[0][0] == "device_deactivated" for event in service.cache.events) == 2
    db.close()


def test_tampered_or_deleted_cache_never_authorizes_activation(tmp_path):
    client = BlockingActivationClient(); service, db = _service_for_blocking(tmp_path, client)
    db.save_activation("p", "tampered", "d", "forged", "active")
    db.connection.execute("UPDATE activation_cache SET status='active', activation_id='forged'")
    db.connection.commit()
    db.connection.execute("DELETE FROM activation_cache"); db.connection.commit()
    service.activate(_validated_product())
    assert client.activation_calls == 1
    assert db.connection.execute("SELECT activation_id FROM activation_cache").fetchone() is not None
    db.close()


def test_concurrent_sqlite_cache_and_audit_writes_are_atomic(tmp_path):
    db = Database(tmp_path / "agent.db")
    barrier = threading.Barrier(8)
    def write(index):
        barrier.wait()
        db.save_activation("p", f"l{index}", "d", f"a{index}", "active")
        db.record_audit_event("activation", "active", "p", "d", f"a{index}")
    threads = [threading.Thread(target=write, args=(index,)) for index in range(8)]
    for thread in threads: thread.start()
    for thread in threads: thread.join(timeout=2)
    assert all(not thread.is_alive() for thread in threads)
    assert db.connection.execute("SELECT COUNT(*) FROM activation_cache").fetchone()[0] == 1
    assert len(db.list_audit_events()) == 8
    db.close()


class IdentityForTest:
    def __init__(self): self.value = "identity-a"; self.generation = 1
    def load_or_create(self): return self.value
    def reset(self): self.generation += 1; self.value = "identity-b"; return self.value


def _service_for_blocking(tmp_path, client):
    db = Database(tmp_path / "agent.db")
    service = LicensingService(client, ActivationSession(), IdentityForTest(), DeviceFingerprint({"platform": "test", "os_version": "1", "architecture": "x64"}), db)
    return service, db


def test_concurrent_activation_deduplicates_and_shares_result(tmp_path):
    client = BlockingActivationClient(); service, db = _service_for_blocking(tmp_path, client)
    service.cache = ThreadSafeCache()
    results = []
    threads = [threading.Thread(target=lambda: results.append(service.activate(_validated_product()))) for _ in range(2)]
    for thread in threads: thread.start()
    assert client.started.wait(timeout=2); client.release.set()
    for thread in threads: thread.join(timeout=2)
    assert client.activation_calls == 1
    assert results[0] == results[1]
    db.close()


class ThreadSafeCache:
    def __init__(self): self.lock = threading.Lock(); self.activations = []; self.events = []
    def save_activation(self, *args):
        with self.lock: self.activations.append(args)
    def record_audit_event(self, *args, **kwargs):
        with self.lock: self.events.append((args, kwargs))
    def invalidate_activation(self, *args):
        with self.lock: self.activations.append(args)


class FailingCache(ThreadSafeCache):
    def __init__(self, operation):
        super().__init__(); self.operation = operation
    def save_activation(self, *args):
        if self.operation == "save": raise OSError("cache write failed")
        super().save_activation(*args)
    def invalidate_activation(self, *args):
        if self.operation == "invalidate": raise OSError("cache reconciliation failed")
        super().invalidate_activation(*args)


class FailingAudit:
    def record_audit_event(self, *args, **kwargs):
        raise OSError("audit write failed")


def test_activation_cache_failure_is_injectable_and_typed(tmp_path):
    client = BlockingActivationClient(); service, db = _service_for_blocking(tmp_path, client)
    service.cache = FailingCache("save")
    with pytest.raises(ActivationPartialFailureError): service.activate(_validated_product())
    db.close()


def test_activation_audit_failure_is_injectable_and_typed(tmp_path):
    client = BlockingActivationClient(); service, db = _service_for_blocking(tmp_path, client)
    service.cache = ThreadSafeCache(); service.audit = FailingAudit()
    with pytest.raises(ActivationPartialFailureError): service.activate(_validated_product())
    db.close()


def test_deactivation_reconciliation_failure_is_injectable_and_typed(tmp_path):
    client = BlockingActivationClient(); service, db = _service_for_blocking(tmp_path, client)
    service.cache = FailingCache("invalidate")
    with pytest.raises(DeactivationPartialFailureError):
        service.deactivate(_validated_product(), "a", "d")
    db.close()


def test_activation_failure_propagates_to_waiters(tmp_path):
    client = BlockingActivationClient(failure=RuntimeError("remote failure")); service, db = _service_for_blocking(tmp_path, client)
    errors = []
    threads = [threading.Thread(target=lambda: _capture(errors, service.activate, _validated_product())) for _ in range(2)]
    for thread in threads: thread.start()
    assert client.started.wait(timeout=2); client.release.set()
    for thread in threads: thread.join(timeout=2)
    assert len(errors) == 2 and all(str(error) == "remote failure" for error in errors)
    db.close()


@pytest.mark.parametrize("invalidator", ["logout", "session replacement"])
def test_activation_rejects_logout_or_session_replacement(tmp_path, invalidator):
    client = BlockingActivationClient(); service, db = _service_for_blocking(tmp_path, client)
    service.cache = ThreadSafeCache()
    errors = []
    thread = threading.Thread(target=lambda: _capture(errors, service.activate, _validated_product()))
    thread.start()
    assert client.started.wait(timeout=2)
    service.sessions.generation = 2
    client.release.set(); thread.join(timeout=2)
    assert len(errors) == 1 and isinstance(errors[0], MissingSessionError)
    assert not any(item[-1] == "active" for item in service.cache.activations)
    assert not any(event[0][0] == "activation_succeeded" for event in service.cache.events)
    db.close()


def test_activation_rejects_installation_identity_reset(tmp_path):
    client = BlockingActivationClient(); service, db = _service_for_blocking(tmp_path, client)
    service.cache = ThreadSafeCache()
    errors = []
    thread = threading.Thread(target=lambda: _capture(errors, service.activate, _validated_product()))
    thread.start()
    assert client.started.wait(timeout=2)
    service.identity.reset()
    client.release.set(); thread.join(timeout=2)
    assert len(errors) == 1 and isinstance(errors[0], MissingSessionError)
    assert not any(item[-1] == "active" for item in service.cache.activations)
    db.close()


def test_newer_deactivation_invalidates_inflight_activation(tmp_path):
    client = BlockingActivationClient(); service, db = _service_for_blocking(tmp_path, client)
    service.cache = ThreadSafeCache()
    errors = []
    activation = threading.Thread(target=lambda: _capture(errors, service.activate, _validated_product()))
    activation.start()
    assert client.started.wait(timeout=2)
    assert service.deactivate(_validated_product(), "old", "d") is True
    client.release.set(); activation.join(timeout=2)
    assert len(errors) == 1 and isinstance(errors[0], MissingSessionError)
    assert not any(item[-1] == "active" for item in service.cache.activations)
    db.close()


def test_newer_activation_invalidates_inflight_deactivation(tmp_path):
    client = BlockingActivationClient(); service, db = _service_for_blocking(tmp_path, client)
    service.cache = ThreadSafeCache()
    deactivation_started = threading.Event(); release_deactivation = threading.Event()
    original_deactivate = client.deactivate
    def blocked_deactivate(request, token):
        deactivation_started.set(); release_deactivation.wait(timeout=2)
        return original_deactivate(request, token)
    client.deactivate = blocked_deactivate
    errors = []
    deactivation = threading.Thread(target=lambda: _capture(errors, service.deactivate, _validated_product(), "old", "d"))
    deactivation.start()
    assert deactivation_started.wait(timeout=2)
    activation_errors = []
    activation = threading.Thread(target=lambda: _capture(activation_errors, service.activate, _validated_product()))
    activation.start()
    assert client.started.wait(timeout=2)
    client.release.set(); release_deactivation.set()
    activation.join(timeout=2); deactivation.join(timeout=2)
    assert activation_errors == []
    assert len(errors) == 1 and isinstance(errors[0], MissingSessionError)
    assert service.cache.activations and service.cache.activations[-1][-1] == "active"
    db.close()


def _capture(target, function, *args):
    try: function(*args)
    except Exception as exc: target.append(exc)


@pytest.mark.parametrize("status", ["revoked", "expired", "suspended", "inactive", "unknown"])
def test_verification_non_active_states_fail_closed(tmp_path, status):
    client = BlockingActivationClient(verification_status=status, verification_valid=False); service, db = _service_for_blocking(tmp_path, client)
    with pytest.raises(Exception): service.activate(_validated_product())
    assert db.connection.execute("SELECT COUNT(*) FROM activation_cache").fetchone()[0] == 0
    db.close()


def test_manifest_provenance_direct_object_rejected():
    from bke_licensing_agent.licensing.errors import ManifestProvenanceError
    with pytest.raises(ManifestProvenanceError): LicensingService(None, None, None, None).activate(Manifest(schemaVersion=1, productId="p", displayName="P", version="1.0.0", entryPoint="app", updateChannel="stable", minimumAgentVersion="1.0.0", platform="linux", architecture="x64"))
