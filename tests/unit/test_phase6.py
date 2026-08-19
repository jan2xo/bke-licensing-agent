from datetime import datetime, timedelta, timezone
import base64
import json
import threading

import pytest

from bke_licensing_agent.auth.errors import MissingSessionError
from bke_licensing_agent.licensing.authorization import AuthorizationService, AuthorizationState
from bke_licensing_agent.licensing.lease import (
    LicenseLease, LeaseInvalidSignatureError, LeaseMalformedError, LeaseRevokedError,
    LeaseSupersededError, LeaseUnknownKeyError, LeaseVerifier,
)
from bke_licensing_agent.licensing.lease_storage import LeaseMetadataRepository
from bke_licensing_agent.licensing.reconciliation import (
    LeaseReconciliationService, ReconciliationState,
)
from bke_licensing_agent.licensing.refresh import LeaseRefreshService, RefreshState
from bke_licensing_agent.licensing.launch_authorization import (
    AuthorizationReason, LaunchAuthorizationService,
)
from bke_licensing_agent.api.errors import ResourceNotFoundError
from bke_licensing_agent.storage.database import Database
from bke_licensing_agent.manifest.validator import validate_manifest


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _capture(target, function, *args):
    try:
        function(*args)
    except Exception as exc:
        target.append(exc)


def product():
    return validate_manifest({"schemaVersion": 1, "productId": "p", "displayName": "P",
        "version": "1.0.0", "entryPoint": "app", "updateChannel": "stable",
        "minimumAgentVersion": "1.0.0", "platform": "linux", "architecture": "x64"})


def lease(**changes):
    values = dict(license_id="license-l", lease_id="l", generation=1, product_id="p", installation_id="i",
        device_id="d", version="1.0.0", issuer="bke", issued_at=NOW,
        not_before=NOW - timedelta(minutes=1), expires_at=NOW + timedelta(hours=1),
        key_id="k", algorithm="Ed25519")
    values.update(changes)
    return LicenseLease(**values)


@pytest.mark.parametrize("state, changes", [
    (AuthorizationState.LEASE_EXPIRED, {"expires_at": NOW - timedelta(minutes=1)}),
    (AuthorizationState.LEASE_NOT_YET_VALID, {"not_before": NOW + timedelta(minutes=2)}),
    (AuthorizationState.LEASE_WRONG_PRODUCT, {"product_id": "other"}),
    (AuthorizationState.LEASE_WRONG_INSTALLATION, {"installation_id": "other"}),
    (AuthorizationState.LEASE_WRONG_DEVICE, {"device_id": "other"}),
    (AuthorizationState.LEASE_VERSION_REJECTED, {"version": "2.0.0"}),
])
def test_offline_authorization_fails_closed(state, changes):
    decision = AuthorizationService(clock=lambda: NOW).authorize(product(), lease(**changes), "i", "d")
    assert decision.state is state and not decision.authorized


def test_offline_authorization_accepts_valid_lease():
    decision = AuthorizationService(clock=lambda: NOW).authorize(product(), lease(), "i", "d")
    assert decision.state is AuthorizationState.AUTHORIZED


def test_untrusted_key_is_rejected_before_signature_work():
    with pytest.raises(LeaseUnknownKeyError):
        LeaseVerifier({}).verify({"payload": "e30=", "signature": "eA==", "key_id": "unknown", "algorithm": "Ed25519"})


def test_malformed_envelope_is_rejected():
    with pytest.raises(LeaseMalformedError): LeaseVerifier({"k": "bad"}).verify({})


def test_revoked_and_superseded_leases_are_rejected_after_signature_boundary():
    assert lease(revoked=True).revoked
    assert lease(superseded_by="new").superseded_by == "new"
    assert LeaseRevokedError and LeaseSupersededError


def signed_lease(private_key, **changes):
    payload = lease(**changes).model_dump_json()
    signature = private_key.sign(payload.encode())
    from cryptography.hazmat.primitives import serialization
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    envelope = {"payload": payload, "signature": base64.b64encode(signature).decode(),
        "key_id": "k", "algorithm": "Ed25519"}
    return envelope, public_key


def test_valid_ed25519_signature_and_pem_key_verification():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    private_key = Ed25519PrivateKey.generate()
    envelope, public_key = signed_lease(private_key)
    verified = LeaseVerifier({"k": public_key}).verify(envelope)
    assert verified.lease_id == "l"


@pytest.mark.parametrize("mutation", ["payload", "signature"])
def test_altered_signed_lease_is_rejected(mutation):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    private_key = Ed25519PrivateKey.generate()
    envelope, public_key = signed_lease(private_key)
    if mutation == "payload":
        data = json.loads(envelope["payload"]); data["device_id"] = "tampered"
        envelope["payload"] = json.dumps(data, separators=(",", ":"))
    else:
        envelope["signature"] = base64.b64encode(b"bad").decode()
    with pytest.raises(LeaseInvalidSignatureError): LeaseVerifier({"k": public_key}).verify(envelope)


@pytest.mark.parametrize("changes, error", [
    ({"revoked": True}, LeaseRevokedError),
    ({"superseded_by": "new"}, LeaseSupersededError),
])
def test_signed_revoked_or_superseded_lease_is_rejected(changes, error):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    private_key = Ed25519PrivateKey.generate()
    envelope, public_key = signed_lease(private_key, **changes)
    with pytest.raises(error): LeaseVerifier({"k": public_key}).verify(envelope)


def metadata(**changes):
    values = dict(lease_id="l", product_id="p", installation_id="i", device_id="d",
        generation=1, status="verified", issuer="bke", issued_at=NOW,
        expires_at=NOW + timedelta(hours=1), key_id="k", verified_at=NOW)
    values.update(changes)
    from bke_licensing_agent.licensing.lease import LeaseMetadata
    return LeaseMetadata(**values)


def test_lease_metadata_save_load_replace_delete_and_idempotence(tmp_path):
    with Database(tmp_path / "agent.db") as db:
        repository = LeaseMetadataRepository(db)
        repository.save(metadata())
        assert repository.load("l").product_id == "p"
        repository.save(metadata(status="expired", generation=2))
        assert repository.load("l").status == "expired"
        repository.save(metadata(status="expired", generation=2))
        assert db.connection.execute("SELECT COUNT(*) FROM lease_metadata").fetchone()[0] == 1
        repository.delete("l")
        assert repository.load("l") is None


def test_lease_metadata_migration_is_current_and_idempotent(tmp_path):
    with Database(tmp_path / "agent.db") as db:
        assert db.connection.execute("SELECT version FROM schema_version").fetchone()[0] == 7
        assert db.connection.execute("SELECT name FROM sqlite_master WHERE name='lease_metadata'").fetchone()
    with Database(tmp_path / "agent.db") as db:
        assert db.connection.execute("SELECT version FROM schema_version").fetchone()[0] == 7


def test_lease_metadata_does_not_store_sensitive_fields(tmp_path):
    with Database(tmp_path / "agent.db") as db:
        LeaseMetadataRepository(db).save(metadata())
        columns = {row[1] for row in db.connection.execute("PRAGMA table_info(lease_metadata)")}
        assert not columns & {"signature", "public_key", "access_token", "refresh_token", "payload"}


def test_tampered_lease_metadata_fails_closed(tmp_path):
    from bke_licensing_agent.licensing.lease import LeaseMetadataCorruptError
    with Database(tmp_path / "agent.db") as db:
        repository = LeaseMetadataRepository(db)
        repository.save(metadata())
        db.connection.execute("UPDATE lease_metadata SET generation='not-an-integer'")
        db.connection.commit()
        with pytest.raises(LeaseMetadataCorruptError): repository.load("l")


def test_lease_metadata_sqlite_failure_is_typed(tmp_path):
    from bke_licensing_agent.licensing.lease import LeaseMetadataPersistenceError
    with Database(tmp_path / "agent.db") as db:
        repository = LeaseMetadataRepository(db)
        db.connection.close()
        with pytest.raises(LeaseMetadataPersistenceError): repository.save(metadata())


class ReconcileSessions:
    generation = 1
    def current_session(self): return object()
    def access_token(self): return "token"
    def is_generation_current(self, generation): return generation == self.generation


class ReconcileIdentity:
    generation = 1
    def load_or_create(self): return "i"


def reconciliation_service(tmp_path, envelope):
    from bke_licensing_agent.licensing.lease import LeaseEnvelope
    class Client:
        def retrieve_lease(self, product_id, token): return LeaseEnvelope.model_validate(envelope)
    db = Database(tmp_path / "agent.db")
    repository = LeaseMetadataRepository(db)
    verifier = LeaseVerifier({"k": PUBLIC_KEY})
    return LeaseReconciliationService(Client(), ReconcileSessions(), ReconcileIdentity(),
        verifier, repository, lambda: NOW), db, repository


PUBLIC_KEY = ""


def test_reconciliation_first_update_and_unchanged(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    global PUBLIC_KEY
    private_key = Ed25519PrivateKey.generate()
    envelope, PUBLIC_KEY = signed_lease(private_key)
    service, db, repository = reconciliation_service(tmp_path, envelope)
    assert service.reconcile(product(), "d").state is ReconciliationState.UPDATED
    assert service.reconcile(product(), "d").state is ReconciliationState.UNCHANGED
    db.close()


@pytest.mark.parametrize("changes, state", [
    ({"revoked": True}, ReconciliationState.REVOKED),
    ({"superseded_by": "new"}, ReconciliationState.SUPERSEDED),
])
def test_reconciliation_revoked_or_superseded_removes_metadata(tmp_path, changes, state):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    global PUBLIC_KEY
    private_key = Ed25519PrivateKey.generate()
    valid, PUBLIC_KEY = signed_lease(private_key)
    service, db, repository = reconciliation_service(tmp_path, valid)
    service.reconcile(product(), "d")
    revoked, _ = signed_lease(private_key, **changes)
    service.client.retrieve_lease = lambda product_id, token: type("Envelope", (), {"model_dump": lambda self: revoked})()
    assert service.reconcile(product(), "d").state is state
    assert repository.load("l") is None
    db.close()


def test_reconciliation_expired_and_deleted_results(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    global PUBLIC_KEY
    private_key = Ed25519PrivateKey.generate()
    expired, PUBLIC_KEY = signed_lease(private_key, expires_at=NOW - timedelta(hours=1))
    service, db, repository = reconciliation_service(tmp_path, expired)
    assert service.reconcile(product(), "d").state is ReconciliationState.EXPIRED
    service.client.retrieve_lease = lambda product_id, token: (_ for _ in ()).throw(ResourceNotFoundError("missing"))
    assert service.reconcile(product(), "d").state is ReconciliationState.DELETED
    db.close()


@pytest.mark.parametrize("field", ["product_id", "installation_id", "device_id", "version"])
def test_reconciliation_identity_or_version_mismatch_is_invalid(tmp_path, field):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    global PUBLIC_KEY
    private_key = Ed25519PrivateKey.generate()
    changes = {field: "wrong"}
    envelope, PUBLIC_KEY = signed_lease(private_key, **changes)
    service, db, _ = reconciliation_service(tmp_path, envelope)
    assert service.reconcile(product(), "d", version="1.0.0").state is ReconciliationState.INVALID
    db.close()


def test_reconciliation_does_not_downgrade_newer_metadata(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    global PUBLIC_KEY
    private_key = Ed25519PrivateKey.generate()
    newer, PUBLIC_KEY = signed_lease(private_key, lease_id="new", generation=2)
    service, db, repository = reconciliation_service(tmp_path, newer)
    assert service.reconcile(product(), "d").state is ReconciliationState.UPDATED
    older, _ = signed_lease(private_key, lease_id="old", generation=1)
    service.client.retrieve_lease = lambda product_id, token: type("Envelope", (), {"model_dump": lambda self: older})()
    assert service.reconcile(product(), "d").state is ReconciliationState.INVALID
    assert repository.load("new") is not None and repository.load("old") is None
    db.close()


def test_concurrent_reconciliation_deduplicates(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    global PUBLIC_KEY
    private_key = Ed25519PrivateKey.generate()
    envelope, PUBLIC_KEY = signed_lease(private_key)
    service, db, _ = reconciliation_service(tmp_path, envelope)
    started, release = threading.Event(), threading.Event()
    calls = []
    def retrieve(product_id, token):
        calls.append(1); started.set(); release.wait(timeout=2)
        return type("Envelope", (), {"model_dump": lambda self: envelope})()
    service.client.retrieve_lease = retrieve
    results = []
    threads = [threading.Thread(target=lambda: results.append(service.reconcile(product(), "d"))) for _ in range(2)]
    for thread in threads: thread.start()
    assert started.wait(timeout=2); release.set()
    for thread in threads: thread.join(timeout=2)
    assert len(calls) == 1 and len(results) == 2 and results[0] == results[1]
    db.close()


def test_logout_and_identity_reset_during_reconciliation_reject_result(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    global PUBLIC_KEY
    private_key = Ed25519PrivateKey.generate()
    envelope, PUBLIC_KEY = signed_lease(private_key)
    service, db, repository = reconciliation_service(tmp_path, envelope)
    started, release = threading.Event(), threading.Event()
    def retrieve(product_id, token):
        started.set(); release.wait(timeout=2)
        return type("Envelope", (), {"model_dump": lambda self: envelope})()
    service.client.retrieve_lease = retrieve
    errors = []
    thread = threading.Thread(target=lambda: _capture(errors, service.reconcile, product(), "d"))
    thread.start(); assert started.wait(timeout=2)
    service.sessions.generation = 2
    release.set(); thread.join(timeout=2)
    assert errors and isinstance(errors[0], MissingSessionError)
    assert repository.load("l") is None
    db.close()


def test_identity_reset_during_reconciliation_rejects_result(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    global PUBLIC_KEY
    private_key = Ed25519PrivateKey.generate()
    envelope, PUBLIC_KEY = signed_lease(private_key)
    service, db, repository = reconciliation_service(tmp_path, envelope)
    started, release = threading.Event(), threading.Event()
    service.client.retrieve_lease = lambda product_id, token: (started.set(), release.wait(timeout=2), type("Envelope", (), {"model_dump": lambda self: envelope})())[2]
    errors = []
    thread = threading.Thread(target=lambda: _capture(errors, service.reconcile, product(), "d"))
    thread.start(); assert started.wait(timeout=2)
    service.identity.generation = 2
    release.set(); thread.join(timeout=2)
    assert errors and isinstance(errors[0], MissingSessionError)
    assert repository.load("l") is None
    db.close()


def test_refresh_no_refresh_required_and_refreshes_expiring_lease(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    global PUBLIC_KEY
    private_key = Ed25519PrivateKey.generate()
    envelope, PUBLIC_KEY = signed_lease(private_key, expires_at=NOW + timedelta(hours=2))
    service, db, _ = reconciliation_service(tmp_path, envelope)
    refresh = LeaseRefreshService(service, threshold=timedelta(hours=1))
    assert refresh.refresh(product(), "d").state is RefreshState.REFRESHED
    assert refresh.refresh(product(), "d").state is RefreshState.NO_REFRESH_REQUIRED
    db.close()


def test_refresh_rejects_older_generation(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    global PUBLIC_KEY
    private_key = Ed25519PrivateKey.generate()
    newer, PUBLIC_KEY = signed_lease(private_key, generation=2, lease_id="new", expires_at=NOW + timedelta(minutes=1))
    service, db, _ = reconciliation_service(tmp_path, newer)
    refresh = LeaseRefreshService(service, threshold=timedelta(hours=1))
    assert refresh.refresh(product(), "d").state is RefreshState.REFRESHED
    older, _ = signed_lease(private_key, generation=1, lease_id="old", expires_at=NOW + timedelta(minutes=1))
    service.client.retrieve_lease = lambda product_id, token: type("Envelope", (), {"model_dump": lambda self: older})()
    assert refresh.refresh(product(), "d").state is RefreshState.STALE_REJECTED
    db.close()


def test_concurrent_refresh_deduplicates(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    global PUBLIC_KEY
    private_key = Ed25519PrivateKey.generate()
    envelope, PUBLIC_KEY = signed_lease(private_key, expires_at=NOW + timedelta(hours=2))
    service, db, _ = reconciliation_service(tmp_path, envelope)
    started, release = threading.Event(), threading.Event()
    calls = []
    def retrieve(product_id, token):
        calls.append(1); started.set(); release.wait(timeout=2)
        return type("Envelope", (), {"model_dump": lambda self: envelope})()
    service.client.retrieve_lease = retrieve
    refresh = LeaseRefreshService(service, threshold=timedelta(hours=1))
    results = []
    threads = [threading.Thread(target=lambda: results.append(refresh.refresh(product(), "d"))) for _ in range(2)]
    for thread in threads: thread.start()
    assert started.wait(timeout=2); release.set()
    for thread in threads: thread.join(timeout=2)
    assert len(calls) == 1 and results[0] == results[1]
    db.close()


class AuthorizationIdentity:
    generation = 1
    def load_or_create(self): return "i"
    def session_current(self, generation): return generation == 1


def launch_service(tmp_path, private_key):
    envelope, public_key = signed_lease(private_key, expires_at=NOW + timedelta(hours=1))
    db = Database(tmp_path / "agent.db")
    service = LaunchAuthorizationService(LeaseVerifier({"k": public_key}),
        LeaseMetadataRepository(db), lambda: NOW)
    service.observe_trusted_time(NOW)
    return service, envelope, db


def test_valid_offline_launch_authorization_is_decision_only(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    service, envelope, db = launch_service(tmp_path, Ed25519PrivateKey.generate())
    decision = service.authorize(product(), AuthorizationIdentity(), "d", envelope)
    assert decision.allowed and decision.reason is AuthorizationReason.AUTHORIZED_OFFLINE
    db.close()


@pytest.mark.parametrize("reason", [AuthorizationReason.MISSING_LEASE, AuthorizationReason.WRONG_DEVICE])
def test_launch_authorization_fails_closed(reason, tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    service, envelope, db = launch_service(tmp_path, Ed25519PrivateKey.generate())
    if reason is AuthorizationReason.MISSING_LEASE:
        decision = service.authorize(product(), AuthorizationIdentity(), "d", None)
    else:
        decision = service.authorize(product(), AuthorizationIdentity(), "wrong", envelope)
    assert not decision.allowed and decision.reason is reason
    db.close()


def test_launch_authorization_rejects_clock_rollback(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    envelope, public_key = signed_lease(key, expires_at=NOW + timedelta(hours=1))
    db = Database(tmp_path / "agent.db")
    service = LaunchAuthorizationService(LeaseVerifier({"k": public_key}), LeaseMetadataRepository(db),
        lambda: NOW - timedelta(hours=1))
    service.observe_trusted_time(NOW)
    decision = service.authorize(product(), AuthorizationIdentity(), "d", envelope)
    assert not decision.allowed and decision.reason is AuthorizationReason.CLOCK_ROLLBACK_DETECTED
    db.close()


def test_launch_authorization_audit_failure_fails_closed(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    service, envelope, db = launch_service(tmp_path, Ed25519PrivateKey.generate())
    class Audit:
        def record_audit_event(self, *args, **kwargs): raise OSError("audit unavailable")
    service.audit = Audit()
    decision = service.authorize(product(), AuthorizationIdentity(), "d", envelope)
    assert not decision.allowed and decision.reason is AuthorizationReason.AUDIT_FAILED
    db.close()


def test_launch_authorization_concurrent_callers_share_result(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    service, envelope, db = launch_service(tmp_path, key)
    original = service.verifier.verify
    started, release = threading.Event(), threading.Event()
    calls = []

    def verify(value):
        calls.append(1)
        started.set()
        assert release.wait(timeout=2)
        return original(value)

    service.verifier.verify = verify
    results = []
    threads = [threading.Thread(target=lambda: results.append(
        service.authorize(product(), AuthorizationIdentity(), "d", envelope, session_generation=1)
    )) for _ in range(2)]
    for thread in threads:
        thread.start()
    assert started.wait(timeout=2)
    release.set()
    for thread in threads:
        thread.join(timeout=2)
    assert calls == [1]
    assert results[0] == results[1]
    assert results[0].allowed
    db.close()


def test_launch_authorization_failure_is_shared_by_waiters(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    service, envelope, db = launch_service(tmp_path, key)
    original = service.verifier.verify
    started, release = threading.Event(), threading.Event()

    def verify(value):
        started.set()
        assert release.wait(timeout=2)
        envelope_copy = dict(value)
        envelope_copy["signature"] = base64.b64encode(b"bad").decode()
        return original(envelope_copy)

    service.verifier.verify = verify
    results = []
    threads = [threading.Thread(target=lambda: results.append(
        service.authorize(product(), AuthorizationIdentity(), "d", envelope, session_generation=1)
    )) for _ in range(2)]
    for thread in threads:
        thread.start()
    assert started.wait(timeout=2)
    release.set()
    for thread in threads:
        thread.join(timeout=2)
    assert len(results) == 2
    assert results[0] == results[1]
    assert results[0].reason is AuthorizationReason.INVALID_SIGNATURE
    db.close()


def test_launch_authorization_rejects_logout_session_replacement_and_identity_reset(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    service, envelope, db = launch_service(tmp_path, key)
    original = service.verifier.verify
    started, release = threading.Event(), threading.Event()

    def verify(value):
        started.set()
        assert release.wait(timeout=2)
        return original(value)

    service.verifier.verify = verify
    identity = AuthorizationIdentity()
    result = []
    thread = threading.Thread(target=lambda: result.append(
        service.authorize(product(), identity, "d", envelope, session_generation=1)
    ))
    thread.start()
    assert started.wait(timeout=2)
    identity.generation = 2
    identity.session_current = lambda generation: False
    release.set()
    thread.join(timeout=2)
    assert result[0].reason is AuthorizationReason.STALE_OPERATION
    assert not result[0].allowed
    db.close()


@pytest.mark.parametrize("payload", [{}, {"payload": "bad"}, {"payload": "", "signature": "", "key_id": "k", "algorithm": "Bad"}])
def test_launch_authorization_malformed_matrix_fails_closed(tmp_path, payload):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    service, _, db = launch_service(tmp_path, Ed25519PrivateKey.generate())
    decision = service.authorize(product(), AuthorizationIdentity(), "d", payload)
    assert not decision.allowed
    assert decision.reason is AuthorizationReason.MALFORMED_LEASE
    db.close()


def test_launch_authorization_rejects_stale_generation_and_revision(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    service, envelope, db = launch_service(tmp_path, key)
    service.repository.save(metadata(generation=2, server_revision=3))
    decision = service.authorize(product(), AuthorizationIdentity(), "d", envelope)
    assert not decision.allowed and decision.reason in {
        AuthorizationReason.STALE_LEASE, AuthorizationReason.LEASE_REVOKED,
    }
    db.close()


def test_launch_authorization_stale_after_refresh_or_reconciliation(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    service, envelope, db = launch_service(tmp_path, key)
    started, release = threading.Event(), threading.Event()
    original = service.verifier.verify

    def verify(value):
        result = original(value)
        started.set()
        assert release.wait(timeout=2)
        return result

    service.verifier.verify = verify
    identity = AuthorizationIdentity()
    results = []
    thread = threading.Thread(target=lambda: results.append(
        service.authorize(product(), identity, "d", envelope)
    ))
    thread.start()
    assert started.wait(timeout=2)
    service.repository.save(metadata(generation=2, server_revision=2, lease_id="new"))
    release.set()
    thread.join(timeout=2)
    assert not results[0].allowed
    assert results[0].reason is AuthorizationReason.STALE_LEASE
    db.close()


def test_launch_authorization_replay_is_rejected_after_restart_and_supersedence(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    service, envelope, db = launch_service(tmp_path, key)
    service.repository.save(metadata(generation=3, server_revision=4, lease_id="current"))
    db.close()
    restarted = Database(tmp_path / "agent.db")
    service = LaunchAuthorizationService(
        LeaseVerifier({"k": service.verifier.trusted_keys["k"]}),
        LeaseMetadataRepository(restarted), lambda: NOW,
    )
    service.observe_trusted_time(NOW)
    decision = service.authorize(product(), AuthorizationIdentity(), "d", envelope)
    assert not decision.allowed and decision.reason is AuthorizationReason.STALE_LEASE
    restarted.close()


def test_sqlite_audit_transaction_rollback_and_concurrent_writes(tmp_path):
    db = Database(tmp_path / "agent.db")
    barrier = threading.Barrier(2)
    errors = []

    def write(index):
        try:
            barrier.wait(timeout=2)
            db.record_audit_event("authorization", f"r{index}", "p", "d", f"l{index}")
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=write, args=(index,)) for index in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=2)
    assert not errors
    assert len(db.list_audit_events()) == 2
    import sqlite3
    db.connection.set_authorizer(
        lambda action, *_: sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_INSERT
        else sqlite3.SQLITE_OK
    )
    with pytest.raises(sqlite3.DatabaseError):
        db.record_audit_event("authorization", "failed")
    db.connection.set_authorizer(None)
    assert len(db.list_audit_events()) == 2
    db.close()


def test_allowed_and_denied_authorization_audit_failures_are_explicit(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    service, envelope, db = launch_service(tmp_path, Ed25519PrivateKey.generate())

    class BrokenAudit:
        def record_audit_event(self, *args, **kwargs):
            raise OSError("unavailable")

    service.audit = BrokenAudit()
    allowed = service.authorize(product(), AuthorizationIdentity(), "d", envelope)
    denied = service.authorize(product(), AuthorizationIdentity(), "wrong", envelope)
    assert not allowed.allowed and allowed.reason is AuthorizationReason.AUDIT_FAILED
    assert not denied.allowed and denied.reason is AuthorizationReason.AUDIT_FAILED
    db.close()


def test_authorization_decision_propagates_execution_binding(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    service, envelope, db = launch_service(tmp_path, Ed25519PrivateKey.generate())
    identity = AuthorizationIdentity()
    result = service.authorize(product(), identity, "d", envelope)
    assert result.installation_id == "i"
    assert result.installation_generation == 1
    assert result.device_id == "d"
    assert result.product_version == "1.0.0"
    db.close()


class _AuditCapture:
    def __init__(self):
        self.events = []

    def record_audit_event(self, event_type, result, **kwargs):
        self.events.append((event_type, result, kwargs))


def _proof_service(tmp_path, generation=1, revision=1, status="verified"):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    envelope, public_key = signed_lease(key, generation=generation, server_revision=revision)
    db = Database(tmp_path / "agent.db")
    repository = LeaseMetadataRepository(db)
    if generation > 1 or revision > 1 or status != "verified":
        repository.save(metadata(generation=generation, server_revision=revision,
                                 status=status, lease_id="current"))
    audit = _AuditCapture()
    service = LaunchAuthorizationService(LeaseVerifier({"k": public_key}), repository,
        lambda: NOW, audit=audit)
    service.observe_trusted_time(NOW)
    return service, envelope, repository, audit, db, key


def _blocked_authorization(service, envelope, identity, mutate):
    original = service.verifier.verify
    started, release = threading.Event(), threading.Event()

    def verify(value):
        result = original(value)
        started.set()
        assert release.wait(timeout=2)
        return result

    service.verifier.verify = verify
    result = []
    thread = threading.Thread(target=lambda: result.append(
        service.authorize(product(), identity, "d", envelope)
    ))
    thread.start()
    assert started.wait(timeout=2)
    mutate()
    release.set()
    thread.join(timeout=2)
    return result[0]


def test_authorization_started_before_refresh_is_rejected_after_refresh(tmp_path):
    service, envelope, repository, audit, db, _ = _proof_service(tmp_path)
    decision = _blocked_authorization(service, envelope, AuthorizationIdentity(),
        lambda: repository.save(metadata(generation=2, server_revision=2, lease_id="refresh")))
    assert not decision.allowed and decision.reason is AuthorizationReason.STALE_LEASE
    assert all(event[1] != AuthorizationReason.AUTHORIZED_OFFLINE.value for event in audit.events)
    assert repository.latest("p", "d").generation == 2
    db.close()


def test_authorization_started_after_refresh_uses_current_lease(tmp_path):
    service, envelope, repository, audit, db, key = _proof_service(tmp_path)
    newer, public_key = signed_lease(key, generation=2, server_revision=2, lease_id="refresh")
    service.verifier = LeaseVerifier({"k": public_key})
    repository.save(metadata(generation=2, server_revision=2, lease_id="refresh"))
    decision = service.authorize(product(), AuthorizationIdentity(), "d", newer)
    assert decision.allowed and decision.lease_id == "refresh"
    assert any(event[1] == AuthorizationReason.AUTHORIZED_OFFLINE.value for event in audit.events)
    db.close()


def test_authorization_started_before_reconciliation_revocation_is_rejected(tmp_path):
    service, envelope, repository, audit, db, _ = _proof_service(tmp_path)
    decision = _blocked_authorization(service, envelope, AuthorizationIdentity(),
        lambda: repository.save(metadata(generation=2, server_revision=2, status="revoked", lease_id="revoked")))
    assert not decision.allowed and decision.reason is AuthorizationReason.LEASE_REVOKED
    assert not any(event[1] == AuthorizationReason.AUTHORIZED_OFFLINE.value for event in audit.events)
    db.close()


def test_authorization_started_after_reconciliation_observes_revocation(tmp_path):
    service, envelope, repository, audit, db, _ = _proof_service(
        tmp_path, generation=2, revision=2, status="revoked")
    decision = service.authorize(product(), AuthorizationIdentity(), "d", envelope)
    assert not decision.allowed and decision.reason is AuthorizationReason.LEASE_REVOKED
    assert not any(event[1] == AuthorizationReason.AUTHORIZED_OFFLINE.value for event in audit.events)
    db.close()


@pytest.mark.parametrize("transition", ["refresh", "reconciliation", "revocation", "supersedence"])
def test_replay_rejected_after_refresh(tmp_path, transition):
    service, envelope, repository, audit, db, _ = _proof_service(tmp_path)
    status = "revoked" if transition == "revocation" else "superseded" if transition == "supersedence" else "verified"
    repository.save(metadata(generation=2, server_revision=2, status=status, lease_id=transition))
    decision = service.authorize(product(), AuthorizationIdentity(), "d", envelope)
    assert not decision.allowed and decision.reason in {
        AuthorizationReason.STALE_LEASE, AuthorizationReason.LEASE_REVOKED,
        AuthorizationReason.LEASE_SUPERSEDED,
    }
    assert not any(event[1] == AuthorizationReason.AUTHORIZED_OFFLINE.value for event in audit.events)
    db.close()


def test_replay_rejected_after_reconciliation(tmp_path):
    service, envelope, repository, _, db, _ = _proof_service(tmp_path)
    repository.save(metadata(generation=2, server_revision=2, lease_id="reconciliation"))
    decision = service.authorize(product(), AuthorizationIdentity(), "d", envelope)
    assert not decision.allowed and decision.reason is AuthorizationReason.STALE_LEASE
    db.close()


def test_replay_rejected_after_revocation(tmp_path):
    service, envelope, repository, _, db, _ = _proof_service(tmp_path)
    repository.save(metadata(generation=2, server_revision=2, status="revoked", lease_id="revocation"))
    decision = service.authorize(product(), AuthorizationIdentity(), "d", envelope)
    assert not decision.allowed and decision.reason is AuthorizationReason.LEASE_REVOKED
    db.close()


def test_replay_rejected_after_supersedence(tmp_path):
    service, envelope, repository, _, db, _ = _proof_service(tmp_path)
    repository.save(metadata(generation=2, server_revision=2, status="superseded", lease_id="supersedence"))
    decision = service.authorize(product(), AuthorizationIdentity(), "d", envelope)
    assert not decision.allowed and decision.reason is AuthorizationReason.LEASE_SUPERSEDED
    db.close()


def test_stale_authorization_invalidated_by_refresh_replacement(tmp_path):
    test_authorization_started_before_refresh_is_rejected_after_refresh(tmp_path)


def test_stale_authorization_invalidated_by_reconciliation_replacement(tmp_path):
    test_authorization_started_before_reconciliation_revocation_is_rejected(tmp_path)


def test_stale_authorization_invalidated_by_revocation(tmp_path):
    test_replay_rejected_after_revocation(tmp_path)


def test_stale_authorization_invalidated_by_supersedence(tmp_path):
    test_replay_rejected_after_supersedence(tmp_path)
