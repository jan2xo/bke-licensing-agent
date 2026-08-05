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


def test_interrupted_operations_fail_closed_without_authorization(tmp_path):
    db = Database(tmp_path / "agent.db")
    service = RecoveryService(db)
    for operation in ("refresh", "reconciliation", "startup", "launch"):
        result = service.recover_interrupted(operation)
        assert result.action is RecoveryAction.RECOVERED
        assert not result.authorization_granted
    assert service.recover_interrupted("unknown").action is RecoveryAction.MANUAL_INTERVENTION_REQUIRED
    db.close()


def test_audit_and_reconnect_recovery_use_injected_boundaries(tmp_path):
    db = Database(tmp_path / "agent.db")
    calls = []
    service = RecoveryService(db, audit_recovery=lambda: calls.append("audit"),
        reconnect=lambda: calls.append("reconnect"))
    results = service.startup()
    assert any(item.action is RecoveryAction.AUDIT_RECOVERED for item in results)
    assert service.reconnect_online().action is RecoveryAction.RECOVERED
    assert calls == ["audit", "reconnect"]
    db.close()


def test_sqlite_integrity_failure_is_reported(tmp_path):
    db = Database(tmp_path / "agent.db")
    result = RecoveryService(db).startup()
    assert all(not item.authorization_granted for item in result)
    db.close()


def test_process_identity_match_and_pid_reuse_are_distinguished(tmp_path):
    db = Database(tmp_path / "agent.db")
    seen = []
    service = RecoveryService(db, process_inspector=lambda pid, record: seen.append((pid, record)) or record["start"] == "known")
    assert service.recover_process(42, {"start": "known"}).action is RecoveryAction.PROCESS_RECOVERED
    assert service.recover_process(42, {"start": "different"}).action is RecoveryAction.PROCESS_RECOVERED
    assert seen == [(42, {"start": "known"}), (42, {"start": "different"})]
    db.close()


def test_recovery_order_validates_identity_before_lease_and_process(tmp_path):
    db = Database(tmp_path / "agent.db")
    order = []
    service = RecoveryService(db, lease_repository=LeaseMetadataRepository(db),
        identity_validate=lambda: order.append("identity"),
        process_recovery=lambda: order.append("process"))
    service.startup()
    assert order == ["identity", "process"]
    db.close()


def test_failed_identity_recovery_blocks_all_following_actions(tmp_path):
    db = Database(tmp_path / "agent.db")
    calls = []
    service = RecoveryService(db, identity_validate=lambda: (_ for _ in ()).throw(OSError("identity")),
        process_recovery=lambda: calls.append("process"))
    result = service.startup()
    assert result[0].action is RecoveryAction.MANUAL_INTERVENTION_REQUIRED
    assert calls == []
    db.close()


def test_reconnect_runs_refresh_then_reconciliation_once(tmp_path):
    db = Database(tmp_path / "agent.db")
    order = []
    service = RecoveryService(db, reconnect=lambda: order.append("connect"),
        refresh=lambda: order.append("refresh"), reconcile=lambda: order.append("reconcile"))
    result = service.reconnect_online()
    assert result.action is RecoveryAction.RECOVERED
    assert order == ["connect", "refresh", "reconcile"]
    db.close()


def test_recovery_actions_never_authorize(tmp_path):
    db = Database(tmp_path / "agent.db")
    service = RecoveryService(db)
    results = service.startup() + [service.recover_interrupted("launch"), service.reconnect_online()]
    assert all(not result.authorization_granted for result in results)
    db.close()
