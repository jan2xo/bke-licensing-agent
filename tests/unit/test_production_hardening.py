import logging
import pytest
from logging.handlers import RotatingFileHandler

from bke_licensing_agent.production import DiagnosticsService, HealthState, ShutdownCoordinator, StartupCoordinator, StartupFailure, RedactingFilter, StartupValidator
from bke_licensing_agent.production.runtime import HealthReport
from test_production import values
from bke_licensing_agent.production import ProductionConfig


def test_diagnostics_are_typed_and_redacted(tmp_path):
    config = ProductionConfig.from_values(values(tmp_path))
    health = HealthReport(HealthState.HEALTHY, True, True, True, True, True)
    report = DiagnosticsService(config, agent_version="1", protocol_version="1",
        schema_version=4, trusted_key_ids=["b", "a"], recovery={"state": "ok"},
        updates={"state": "none"}, health=health, products=[{"product_id": "p"}]).report()
    assert report.trusted_keys == {"key_ids": ("a", "b")}
    assert "token" not in str(report).lower()


def test_shutdown_is_idempotent_and_releases_in_reverse_order():
    events = []
    shutdown = ShutdownCoordinator()
    shutdown.register(lambda: events.append("first"))
    shutdown.register(lambda: events.append("second"))
    shutdown.shutdown(); shutdown.shutdown()
    assert events == ["second", "first"]


def test_startup_order_and_execution_gate():
    order = []
    steps = {name: (lambda name=name: order.append(name)) for name in
        ("configuration", "paths", "trusted_keys", "database", "recovery",
         "updates", "diagnostics", "logging", "health")}
    coordinator = StartupCoordinator(steps)
    coordinator.start()
    assert coordinator.execution_enabled
    assert coordinator.order == list(steps)


def test_startup_failure_keeps_execution_disabled():
    steps = {"configuration": lambda: (_ for _ in ()).throw(StartupFailure("bad"))}
    coordinator = StartupCoordinator(steps)
    with pytest.raises(StartupFailure):
        coordinator.start()
    assert not coordinator.execution_enabled


def test_logging_redaction_and_deterministic_event_id(tmp_path):
    record1 = logging.LogRecord("bke", logging.INFO, "", 0, "token=secret", (), None)
    record2 = logging.LogRecord("bke", logging.INFO, "", 0, "token=secret", (), None)
    filter_ = RedactingFilter()
    assert filter_.filter(record1) and filter_.filter(record2)
    assert record1.msg == "[REDACTED]" and record1.event_id == record2.event_id
    assert "secret" not in record1.getMessage()


def test_rotating_logging_has_bounded_configuration(tmp_path):
    path = tmp_path / "agent.log"
    from bke_licensing_agent.production.runtime import configure_logging
    logger = configure_logging(path, max_bytes=32, backup_count=2)
    handler = next(item for item in logger.handlers if isinstance(item, RotatingFileHandler))
    assert handler.maxBytes == 32 and handler.backupCount == 2
    handler.close()
    logger.handlers.clear()


def test_trusted_key_matrix_and_permissions_fail_closed(tmp_path, monkeypatch):
    config = ProductionConfig.from_values(values(tmp_path))
    validator = StartupValidator(config)
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    (key_dir / "a.pem").write_text("not a key")
    with pytest.raises(StartupFailure):
        validator.validate_permissions(key_dir)
    monkeypatch.setattr("os.access", lambda *args: False)
    with pytest.raises(StartupFailure):
        validator.validate_permissions()
