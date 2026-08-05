from datetime import datetime, timezone

from bke_licensing_agent.recovery import RecoveryAction, RecoveryService
from bke_licensing_agent.storage.database import Database
from bke_licensing_agent.licensing.lease_storage import LeaseMetadataRepository
from bke_licensing_agent.licensing.lease import LeaseMetadata


def metadata():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return LeaseMetadata(lease_id="l", product_id="p", installation_id="i",
        device_id="d", generation=1, status="verified", issuer="bke",
        issued_at=now, expires_at=now, key_id="k", verified_at=now)


def test_clean_startup_recovers_lease_metadata(tmp_path):
    db = Database(tmp_path / "agent.db")
    repository = LeaseMetadataRepository(db)
    repository.save(metadata())
    result = RecoveryService(db, repository).startup()
    assert result[0].action is RecoveryAction.LEASE_RECOVERED
    assert not result[0].authorization_granted
    db.close()


def test_missing_cache_is_recoverable(tmp_path):
    db = Database(tmp_path / "agent.db")
    result = RecoveryService(db, LeaseMetadataRepository(db)).startup()
    assert result[0].action is RecoveryAction.LEASE_RECOVERED
    db.close()


def test_corrupted_cache_fails_closed(tmp_path):
    db = Database(tmp_path / "agent.db")
    db.connection.execute("INSERT INTO lease_metadata VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("l", "p", "i", "d", "bad", "verified", "bke", "bad", "bad", "k", "bad", 0))
    db.connection.commit()
    result = RecoveryService(db, LeaseMetadataRepository(db)).startup()
    assert result[0].action is RecoveryAction.CORRUPTED_STATE
    assert not result[0].authorization_granted
    db.close()


def test_process_recovery_boundary_is_deterministic(tmp_path):
    db = Database(tmp_path / "agent.db")
    calls = []
    result = RecoveryService(db, process_recovery=lambda: calls.append(True)).startup()
    assert result[0].action is RecoveryAction.PROCESS_RECOVERED
    assert calls == [True]
    db.close()
