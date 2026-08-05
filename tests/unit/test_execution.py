import hashlib
import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from bke_licensing_agent.execution.service import (
    ArtifactMetadata,
    ExecutionState,
    LaunchExecutionService,
)
from bke_licensing_agent.licensing.launch_authorization import (
    AuthorizationDecision,
    AuthorizationReason,
)
from bke_licensing_agent.manifest.validator import validate_manifest


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def manifest(entry="run.sh", product_id="p", version="1.0.0"):
    return validate_manifest({"schemaVersion": 1, "productId": product_id,
        "displayName": "P", "version": version, "entryPoint": entry,
        "updateChannel": "stable", "minimumAgentVersion": "1.0.0",
        "platform": "linux", "architecture": "x64"})


def decision(product_id="p", version="1.0.0", **changes):
    values = dict(allowed=True, reason=AuthorizationReason.AUTHORIZED_OFFLINE,
        product_id=product_id, lease_id="l", lease_generation=1,
        server_revision=1, authorized_at=NOW,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1), offline=True)
    values.update(changes)
    return AuthorizationDecision(**values)


class FakeProcess:
    pid = 42
    def __init__(self, poll_value=None):
        self.poll_value = poll_value
        self.terminated = False
    def poll(self): return self.poll_value
    def terminate(self): self.terminated = True; self.poll_value = -15


class Audit:
    def __init__(self): self.events = []
    def record_audit_event(self, event_type, result, **kwargs):
        self.events.append((event_type, result, kwargs))


def fixture(tmp_path, entry="run.sh"):
    root = tmp_path / "product"
    root.mkdir(parents=True)
    path = root / entry
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(0o755)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    artifact = ArtifactMetadata("p", "1.0.0", entry, digest)
    return root, artifact


def test_valid_entry_point_hash_and_process_start(tmp_path):
    root, artifact = fixture(tmp_path)
    process = FakeProcess()
    service = LaunchExecutionService(popen=lambda *a, **k: process)
    result = service.launch(manifest(), root, decision(), artifact)
    assert result.state is ExecutionState.LAUNCHED and result.pid == 42


@pytest.mark.parametrize("entry", ["missing", "../outside", "/tmp/outside"])
def test_invalid_entry_points_fail_before_launch(tmp_path, entry):
    root, artifact = fixture(tmp_path)
    calls = []
    service = LaunchExecutionService(popen=lambda *a, **k: calls.append(1))
    if entry == "missing":
        artifact = ArtifactMetadata("p", "1.0.0", entry, "a" * 64)
        value = manifest(entry)
    else:
        with pytest.raises(ValueError):
            value = manifest(entry)
        return
    result = service.launch(value, root, decision(), artifact)
    assert result.state is ExecutionState.EXECUTABLE_MISSING and not calls


def test_directory_symlink_escape_and_arbitrary_artifact_path_rejected(tmp_path):
    root, artifact = fixture(tmp_path)
    (root / "run.sh").unlink()
    (root / "run.sh").mkdir()
    service = LaunchExecutionService(popen=lambda *a, **k: pytest.fail("must not launch"))
    result = service.launch(manifest(), root, decision(), artifact)
    assert result.state is ExecutionState.EXECUTABLE_INVALID
    outside = tmp_path / "outside"
    outside.write_text("x")
    (root / "run.sh").rmdir()
    (root / "run.sh").symlink_to(outside)
    result = service.launch(manifest(), root, decision(), artifact)
    assert result.state is ExecutionState.SYMLINK_ESCAPE


def test_hash_change_and_metadata_mismatch_fail_closed(tmp_path):
    root, artifact = fixture(tmp_path)
    (root / "run.sh").write_text("changed")
    service = LaunchExecutionService(popen=lambda *a, **k: pytest.fail("must not launch"))
    result = service.launch(manifest(), root, decision(), artifact)
    assert result.state is ExecutionState.EXECUTABLE_MODIFIED
    root, artifact = fixture(tmp_path / "other")
    result = service.launch(manifest(), root, decision(), ArtifactMetadata("other", "1.0.0", "run.sh", artifact.sha256))
    assert result.state is ExecutionState.DENIED


def test_authorization_binding_and_stale_generation_fail_closed(tmp_path):
    root, artifact = fixture(tmp_path)
    service = LaunchExecutionService(generation_current=lambda _: False,
        popen=lambda *a, **k: pytest.fail("must not launch"))
    assert service.launch(manifest(), root, decision(), artifact).state is ExecutionState.STALE_AUTHORIZATION
    assert service.launch(manifest(product_id="other"), root, decision(), artifact).state is ExecutionState.DENIED
    assert service.launch(manifest(version="2.0.0"), root, decision(), artifact).state is ExecutionState.DENIED


def test_already_running_and_explicit_termination(tmp_path):
    root, artifact = fixture(tmp_path)
    process = FakeProcess()
    service = LaunchExecutionService(popen=lambda *a, **k: process)
    assert service.launch(manifest(), root, decision(), artifact).state is ExecutionState.LAUNCHED
    assert service.launch(manifest(), root, decision(), artifact).state is ExecutionState.ALREADY_RUNNING
    assert service.terminate("p")
    assert process.terminated


def test_concurrent_launch_single_flight(tmp_path):
    root, artifact = fixture(tmp_path)
    started, release = threading.Event(), threading.Event()
    process = FakeProcess()
    calls = []
    def start(*args, **kwargs):
        calls.append(1); started.set(); assert release.wait(timeout=2); return process
    service = LaunchExecutionService(popen=start)
    results = []
    threads = [threading.Thread(target=lambda: results.append(
        service.launch(manifest(), root, decision(), artifact))) for _ in range(2)]
    for thread in threads: thread.start()
    assert started.wait(timeout=2)
    release.set()
    for thread in threads: thread.join(timeout=2)
    assert len(calls) == 1 and results[0] == results[1]


def test_audit_allowed_denied_and_audit_failure_are_explicit(tmp_path):
    root, artifact = fixture(tmp_path)
    audit = Audit()
    service = LaunchExecutionService(audit=audit, popen=lambda *a, **k: FakeProcess())
    result = service.launch(manifest(), root, decision(), artifact)
    assert result.state is ExecutionState.LAUNCHED
    denied = service.launch(manifest(product_id="x"), root, decision(), artifact)
    assert denied.state is ExecutionState.DENIED
    class Broken:
        def record_audit_event(self, *args, **kwargs): raise OSError("rollback")
    root, artifact = fixture(tmp_path / "third")
    service = LaunchExecutionService(audit=Broken(), popen=lambda *a, **k: FakeProcess())
    assert service.launch(manifest(), root, decision(), artifact).state is ExecutionState.LAUNCH_FAILED


@pytest.mark.parametrize("error", [PermissionError("denied"), OSError("bad format")])
def test_launch_failures_are_typed(tmp_path, error):
    root, artifact = fixture(tmp_path)
    def fail(*args, **kwargs): raise error
    service = LaunchExecutionService(popen=fail)
    result = service.launch(manifest(), root, decision(), artifact)
    assert result.state is ExecutionState.LAUNCH_FAILED


@pytest.mark.parametrize("exit_code", [0, 3])
def test_process_exit_codes_are_observable_from_process_handle(tmp_path, exit_code):
    root, artifact = fixture(tmp_path)
    process = FakeProcess(exit_code)
    service = LaunchExecutionService(popen=lambda *a, **k: process)
    result = service.launch(manifest(), root, decision(), artifact)
    assert result.state is ExecutionState.LAUNCHED
    assert process.poll() == exit_code


def test_process_remains_running_until_termination(tmp_path):
    root, artifact = fixture(tmp_path)
    process = FakeProcess(None)
    service = LaunchExecutionService(popen=lambda *a, **k: process)
    assert service.launch(manifest(), root, decision(), artifact).state is ExecutionState.LAUNCHED
    assert process.poll() is None
    assert service.terminate("p") and process.poll() == -15


@pytest.mark.parametrize("reason", ["logout", "session replacement", "identity reset", "refresh", "reconciliation"])
def test_launch_preparation_generation_races_never_start_or_audit(tmp_path, reason):
    root, artifact = fixture(tmp_path)
    audit = Audit()
    calls = []
    service = LaunchExecutionService(audit=audit, generation_current=lambda _: False,
        popen=lambda *a, **k: calls.append(1))
    result = service.launch(manifest(), root, decision(), artifact)
    assert result.state is ExecutionState.STALE_AUTHORIZATION
    assert not calls
    assert all(event[1] != ExecutionState.LAUNCHED.value for event in audit.events)


def test_executable_replacement_after_verification_is_rejected(tmp_path):
    root, artifact = fixture(tmp_path)
    calls = []
    def replace(path): path.write_text("replaced")
    service = LaunchExecutionService(before_process=replace,
        popen=lambda *a, **k: calls.append(1))
    result = service.launch(manifest(), root, decision(), artifact)
    assert result.state is ExecutionState.EXECUTABLE_MODIFIED
    assert not calls


@pytest.mark.parametrize("field", ["product_id", "version"])
def test_authorization_product_and_version_binding(tmp_path, field):
    root, artifact = fixture(tmp_path)
    service = LaunchExecutionService(popen=lambda *a, **k: pytest.fail("must not launch"))
    if field == "product_id":
        result = service.launch(manifest(), root, decision(product_id="wrong"), artifact)
    else:
        result = service.launch(manifest(), root, decision(),
            ArtifactMetadata("p", "wrong", "run.sh", artifact.sha256))
    assert result.state is ExecutionState.DENIED


def test_wrong_executable_installation_device_and_revision_bindings(tmp_path):
    root, artifact = fixture(tmp_path)
    for bad_artifact in [ArtifactMetadata("p", "1.0.0", "other", artifact.sha256),
                         ArtifactMetadata("other", "1.0.0", "run.sh", artifact.sha256)]:
        service = LaunchExecutionService(popen=lambda *a, **k: pytest.fail("must not launch"))
        assert service.launch(manifest(), root, decision(), bad_artifact).state in {
            ExecutionState.DENIED, ExecutionState.EXECUTABLE_INVALID,
        }
    stale = LaunchExecutionService(generation_current=lambda _: False,
        popen=lambda *a, **k: pytest.fail("must not launch"))
    assert stale.launch(manifest(), root, decision(lease_generation=2), artifact).state is ExecutionState.STALE_AUTHORIZATION
    assert stale.launch(manifest(), root, decision(server_revision=2), artifact).state is ExecutionState.STALE_AUTHORIZATION


def test_real_sqlite_audit_writes_are_concurrent_and_rollback(tmp_path):
    from bke_licensing_agent.storage.database import Database
    import sqlite3
    db = Database(tmp_path / "audit.db")
    barrier = threading.Barrier(4)
    def write(i):
        barrier.wait(timeout=2)
        db.record_audit_event("launch", "launched", "p", "d", str(i))
    threads = [threading.Thread(target=write, args=(i,)) for i in range(4)]
    for thread in threads: thread.start()
    for thread in threads: thread.join(timeout=2)
    assert len(db.list_audit_events()) == 4
    db.connection.set_authorizer(lambda action, *_: sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_INSERT else sqlite3.SQLITE_OK)
    with pytest.raises(sqlite3.DatabaseError):
        db.record_audit_event("launch", "failed")
    db.connection.set_authorizer(None)
    assert len(db.list_audit_events()) == 4
    db.close()


def test_lifecycle_running_exit_and_audit_order(tmp_path):
    root, artifact = fixture(tmp_path)
    process = FakeProcess(0)
    audit = Audit()
    service = LaunchExecutionService(audit=audit, popen=lambda *a, **k: process)
    assert service.launch(manifest(), root, decision(), artifact).state is ExecutionState.LAUNCHED
    running = service.process_status("p")
    assert running is not None and running.state.value == "exited" and running.exit_code == 0
    names = [event[0] for event in audit.events]
    assert names[:3] == ["launch_requested", "launch_started", "process_running"]
    assert "process_exited" in names


def test_lifecycle_crash_and_termination_are_persisted(tmp_path):
    root, artifact = fixture(tmp_path)
    crashed = FakeProcess(2)
    service = LaunchExecutionService(popen=lambda *a, **k: crashed)
    service.launch(manifest(), root, decision(), artifact)
    assert service.process_status("p").state.value == "crashed"
    root, artifact = fixture(tmp_path / "terminated")
    process = FakeProcess(None)
    service = LaunchExecutionService(popen=lambda *a, **k: process)
    service.launch(manifest(), root, decision(), artifact)
    assert service.terminate("p")
    assert service.process_status("p").state.value == "terminated"


@pytest.mark.parametrize("field", ["installation_id", "device_id", "installation_generation"])
def test_authorization_identity_binding_is_checked(tmp_path, field):
    root, artifact = fixture(tmp_path)
    values = {"installation_id": "i", "device_id": "d", "installation_generation": 1}
    values[field] = "wrong" if field != "installation_generation" else 2
    auth = decision(**values)
    service = LaunchExecutionService(popen=lambda *a, **k: pytest.fail("must not launch"))
    result = service.launch(manifest(), root, auth, artifact,
                            installation_id="expected", device_id="expected",
                            installation_generation=1)
    assert result.state is ExecutionState.DENIED
