import base64
import json
from datetime import datetime, timezone
from pathlib import Path
import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bke_licensing_agent.updates import UpdateService, UpdateState
from bke_licensing_agent.updates.service import ResumeMetadata, ResumeRepository, RollbackState, ResumeMetadataCorruptionError
import threading
from datetime import timedelta


def signed(private, **changes):
    values = dict(product_id="p", version="2.0.0", minimum_agent_version="1.0.0",
        release_channel="stable", artifact_sha256="a" * 64, artifact_size=1,
        publication_timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc).isoformat(), key_id="k")
    values.update(changes)
    payload = json.dumps(values, sort_keys=True, separators=(",", ":")).encode()
    values["signature"] = base64.b64encode(private.sign(payload)).decode()
    return values


def service(key):
    pem = key.public_key().public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return UpdateService({"k": pem}, "1.0.0")


def test_signed_metadata_and_downgrade_rejection(tmp_path):
    key = Ed25519PrivateKey.generate()
    update = signed(key)
    checker = service(key)
    assert checker.evaluate(update.copy(), "1.0.0", "p").state is UpdateState.UPDATE_READY
    assert checker.evaluate(update.copy(), "3.0.0", "p").state is UpdateState.NO_UPDATE
    assert checker.evaluate(signed(key, product_id="x"), "1.0.0", "p").state is UpdateState.INCOMPATIBLE


def test_invalid_signature_channel_and_compatibility_fail_closed(tmp_path):
    key = Ed25519PrivateKey.generate()
    checker = service(key)
    bad = signed(key); bad["signature"] = base64.b64encode(b"bad").decode()
    assert checker.evaluate(bad, "1.0.0", "p").state is UpdateState.VERIFICATION_FAILED
    assert checker.evaluate(signed(key, release_channel="beta"), "1.0.0", "p").state is UpdateState.INCOMPATIBLE
    assert checker.evaluate(signed(key, minimum_agent_version="9.0.0"), "1.0.0", "p").state is UpdateState.INCOMPATIBLE


def test_staging_hash_size_and_cleanup(tmp_path):
    source = tmp_path / "artifact"
    source.write_bytes(b"x")
    key = Ed25519PrivateKey.generate()
    checker = service(key)
    import hashlib
    manifest = signed(key, artifact_sha256=hashlib.sha256(b"x").hexdigest())
    from bke_licensing_agent.updates.service import UpdateManifest
    model = UpdateManifest.model_validate(manifest)
    staging = tmp_path / "stage"
    assert checker.stage(source, staging, model).state is UpdateState.UPDATE_READY
    checker.cleanup(staging)
    assert not staging.exists()


def test_rollback_decisions_are_typed():
    assert UpdateService.rollback(False, "1.0.0", "2.0.0") is RollbackState.ROLLBACK_NOT_REQUIRED
    assert UpdateService.rollback(True, None, "2.0.0") is RollbackState.MANUAL_INTERVENTION_REQUIRED
    assert UpdateService.rollback(True, "1.0.0", "2.0.0") is RollbackState.ROLLBACK_REJECTED
    assert UpdateService.rollback(True, "1.0.0", "2.0.0", True) is RollbackState.ROLLBACK_AVAILABLE


def test_resume_metadata_is_untrusted_and_validated():
    key = Ed25519PrivateKey.generate()
    now = datetime.now(timezone.utc)
    metadata = ResumeMetadata("p", "2.0.0", "a", 10, "a" * 64, 4, "/tmp/a", now)
    assert UpdateService.validate_resume(metadata, now, "p", "2.0.0")
    assert not UpdateService.validate_resume(
        ResumeMetadata("p", "2.0.0", "a", 10, "a" * 64, 11, "/tmp/a", now), now, "p", "2.0.0")
    assert not UpdateService.validate_resume(
        ResumeMetadata("p", "2.0.0", "a", 10, "a" * 64, 4, "/tmp/a", now - timedelta(days=1)),
        now - timedelta(days=2), "p", "2.0.0")


def test_concurrent_update_checks_share_one_fetch():
    key = Ed25519PrivateKey.generate()
    checker = service(key)
    calls = []
    started, release = threading.Event(), threading.Event()
    def fetch():
        calls.append(1); started.set(); release.wait(timeout=2); return signed(key)
    results = []
    threads = [threading.Thread(target=lambda: results.append(checker.check("p", "1.0.0", fetch))) for _ in range(2)]
    for thread in threads: thread.start()
    assert started.wait(timeout=2)
    release.set()
    for thread in threads: thread.join(timeout=2)
    assert len(calls) == 1 and results[0] == results[1]


def test_manifest_malformed_matrix_fails_closed():
    key = Ed25519PrivateKey.generate()
    checker = service(key)
    for field in ("product_id", "version", "artifact_sha256", "artifact_size", "release_channel"):
        value = signed(key)
        value.pop(field, None)
        assert checker.evaluate(value, "1.0.0", "p").state is UpdateState.VERIFICATION_FAILED
    value = signed(key, artifact_sha256="z" * 64)
    assert checker.evaluate(value, "1.0.0", "p").state is UpdateState.VERIFICATION_FAILED
    value = signed(key, release_channel="unknown")
    assert checker.evaluate(value, "1.0.0", "p").state is UpdateState.INCOMPATIBLE


def test_staging_missing_source_hash_size_and_collision_fail_closed(tmp_path):
    key = Ed25519PrivateKey.generate()
    checker = service(key)
    from bke_licensing_agent.updates.service import UpdateManifest
    model = UpdateManifest.model_validate(signed(key, artifact_size=1,
        artifact_sha256=__import__("hashlib").sha256(b"x").hexdigest()))
    missing = checker.stage(tmp_path / "missing", tmp_path / "stage", model)
    assert missing.state is UpdateState.STAGING_FAILED
    source = tmp_path / "source"
    source.write_bytes(b"x")
    stage = tmp_path / "stage2"
    stage.mkdir()
    (stage / "artifact.part").write_bytes(b"old")
    assert checker.stage(source, stage, model).state is UpdateState.STAGING_FAILED


def test_artifact_duplicates_and_empty_list_fail_closed():
    key = Ed25519PrivateKey.generate()
    checker = service(key)
    for artifacts in ([], [{"artifact_id": "a", "path": "x"}, {"artifact_id": "a", "path": "y"}],
                      [{"artifact_id": "a", "path": "x"}, {"artifact_id": "b", "path": "x"}]):
        value = signed(key, artifacts=artifacts)
        assert checker.evaluate(value, "1.0.0", "p").state is UpdateState.VERIFICATION_FAILED


def test_resume_repository_survives_restart_and_clears(tmp_path):
    now = datetime.now(timezone.utc)
    metadata = ResumeMetadata("p", "2.0.0", "a", 10, "a" * 64, 4, "/tmp/a", now)
    path = tmp_path / "resume.json"
    ResumeRepository(path).save(metadata)
    assert ResumeRepository(path).load() == metadata
    ResumeRepository(path).clear()
    assert ResumeRepository(path).load() is None


@pytest.mark.parametrize("failure", [PermissionError("denied"), OSError("disk full")])
def test_injected_filesystem_failures_cleanup_staging(tmp_path, failure):
    key = Ed25519PrivateKey.generate()
    source = tmp_path / "source"
    source.write_bytes(b"x")
    from bke_licensing_agent.updates.service import UpdateManifest
    model = UpdateManifest.model_validate(signed(key, artifact_size=1,
        artifact_sha256=__import__("hashlib").sha256(b"x").hexdigest()))
    stage = tmp_path / "stage"
    def fail(source_path, target_path):
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_bytes(b"partial")
        raise failure
    result = service(key)
    result.copyfile = fail
    assert result.stage(source, stage, model).state is UpdateState.STAGING_FAILED
    assert not (stage / "artifact.part").exists()


def test_source_modification_during_copy_fails_closed_and_cleans(tmp_path):
    key = Ed25519PrivateKey.generate()
    source = tmp_path / "source"
    source.write_bytes(b"x")
    from bke_licensing_agent.updates.service import UpdateManifest
    model = UpdateManifest.model_validate(signed(key, artifact_size=1))
    stage = tmp_path / "stage"
    def modify(source_path, target_path):
        source_path.write_bytes(b"changed")
        target_path.write_bytes(b"x")
    checker = service(key)
    checker.copyfile = modify
    result = checker.stage(source, stage, model)
    assert result.state is UpdateState.VERIFICATION_FAILED
    assert not (stage / "artifact.part").exists()


def test_tampered_and_stale_resume_state_is_rejected(tmp_path):
    path = tmp_path / "resume.json"
    path.write_text("{not-json")
    with pytest.raises(ResumeMetadataCorruptionError):
        ResumeRepository(path).load()
    now = datetime.now(timezone.utc)
    metadata = ResumeMetadata("p", "2.0.0", "a", 10, "a" * 64, 4, "/tmp/a", now)
    assert not UpdateService.validate_resume(metadata, now - timedelta(seconds=1), "p", "2.0.0")


@pytest.mark.parametrize("data", [
    {},
    {"product_id": "p", "target_version": "2.0.0", "artifact_id": "a", "expected_size": "bad",
     "expected_sha256": "a" * 64, "downloaded_bytes": 0, "temporary_path": "/tmp/a", "updated_at": "bad"},
    {"product_id": "p", "target_version": "2.0.0", "artifact_id": "a", "expected_size": 1,
     "expected_sha256": "z" * 64, "downloaded_bytes": 2, "temporary_path": "relative", "updated_at": "bad"},
])
def test_resume_corruption_matrix_has_typed_failure(tmp_path, data):
    path = tmp_path / "resume.json"
    path.write_text(json.dumps(data))
    with pytest.raises(ResumeMetadataCorruptionError):
        ResumeRepository(path).load()


def test_missing_resume_is_distinct_from_corruption(tmp_path):
    assert ResumeRepository(tmp_path / "missing.json").load() is None
