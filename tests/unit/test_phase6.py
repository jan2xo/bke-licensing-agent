from datetime import datetime, timedelta, timezone
import base64
import json

import pytest

from bke_licensing_agent.licensing.authorization import AuthorizationService, AuthorizationState
from bke_licensing_agent.licensing.lease import (
    LicenseLease, LeaseInvalidSignatureError, LeaseMalformedError, LeaseRevokedError,
    LeaseSupersededError, LeaseUnknownKeyError, LeaseVerifier,
)
from bke_licensing_agent.licensing.lease_storage import LeaseMetadataRepository
from bke_licensing_agent.storage.database import Database
from bke_licensing_agent.manifest.validator import validate_manifest


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def product():
    return validate_manifest({"schemaVersion": 1, "productId": "p", "displayName": "P",
        "version": "1.0.0", "entryPoint": "app", "updateChannel": "stable",
        "minimumAgentVersion": "1.0.0", "platform": "linux", "architecture": "x64"})


def lease(**changes):
    values = dict(lease_id="l", generation=1, product_id="p", installation_id="i",
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
        assert db.connection.execute("SELECT version FROM schema_version").fetchone()[0] == 3
        assert db.connection.execute("SELECT name FROM sqlite_master WHERE name='lease_metadata'").fetchone()
    with Database(tmp_path / "agent.db") as db:
        assert db.connection.execute("SELECT version FROM schema_version").fetchone()[0] == 3


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
