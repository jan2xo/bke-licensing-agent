import pytest
from pathlib import Path

from bke_licensing_agent.production import HealthState, ProductionConfig, StartupFailure, StartupValidator


def values(tmp_path):
    return {"environment": "production", "platform_url": "https://example.test",
        "release_channel": "stable", "logging_level": "INFO",
        "config_dir": tmp_path / "config", "database_path": tmp_path / "db",
        "log_path": tmp_path / "agent.log", "runtime_dir": tmp_path / "runtime",
        "staged_updates_dir": tmp_path / "updates"}


def test_production_config_and_startup_validation(tmp_path):
    config = ProductionConfig.from_values(values(tmp_path))
    StartupValidator(config).validate()
    assert config.summary()["environment"] == "production"


@pytest.mark.parametrize("change", [{"release_channel": "unknown"}, {"platform_url": "http://x"}, {"retry_limit": -1}])
def test_invalid_configuration_fails_closed(tmp_path, change):
    data = values(tmp_path); data.update(change)
    with pytest.raises(StartupFailure):
        ProductionConfig.from_values(data)


def test_health_and_unknown_configuration(tmp_path):
    data = values(tmp_path); data["unexpected"] = True
    with pytest.raises(StartupFailure):
        ProductionConfig.from_values(data)
    validator = StartupValidator(ProductionConfig.from_values(values(tmp_path)))
    assert validator.health(storage=True, recovery=True, updates=True, trusted_keys=True).state is HealthState.HEALTHY
    assert validator.health(storage=False, recovery=False, updates=False, trusted_keys=False).state is HealthState.UNAVAILABLE
