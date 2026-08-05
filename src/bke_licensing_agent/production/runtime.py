"""Production configuration and operational validation; no authorization logic."""

import logging
import logging.handlers
import os
import threading
import hashlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from collections.abc import Callable
from urllib.parse import urlparse


class StartupFailure(Exception):
    """Typed production startup validation failure."""


class HealthState(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class ProductionConfig:
    environment: str
    platform_url: str
    release_channel: str
    logging_level: str
    config_dir: Path
    database_path: Path
    log_path: Path
    runtime_dir: Path
    staged_updates_dir: Path
    connect_timeout: float = 5.0
    read_timeout: float = 15.0
    retry_limit: int = 3

    @classmethod
    def from_values(cls, values: dict[str, object]) -> "ProductionConfig":
        allowed = {"environment", "platform_url", "release_channel", "logging_level",
                   "config_dir", "database_path", "log_path", "runtime_dir", "staged_updates_dir",
                   "connect_timeout", "read_timeout", "retry_limit"}
        if set(values) - allowed:
            raise StartupFailure("Unknown production configuration")
        required = {"environment", "platform_url", "release_channel", "logging_level",
                    "config_dir", "database_path", "log_path", "runtime_dir", "staged_updates_dir"}
        if not required <= set(values):
            raise StartupFailure("Missing production configuration")
        environment = str(values["environment"])
        if environment not in {"development", "testing", "staging", "production"}:
            raise StartupFailure("Invalid environment")
        channel = str(values["release_channel"])
        if channel not in {"stable", "beta", "internal"}:
            raise StartupFailure("Invalid release channel")
        url = str(values["platform_url"])
        if urlparse(url).scheme not in {"https"} and environment == "production":
            raise StartupFailure("Production platform URL must use HTTPS")
        connect_value = values.get("connect_timeout", 5.0)
        read_value = values.get("read_timeout", 15.0)
        retry_value = values.get("retry_limit", 3)
        if not isinstance(connect_value, (int, float, str)) or not isinstance(read_value, (int, float, str)) or not isinstance(retry_value, (int, str)):
            raise StartupFailure("Invalid timeout or retry configuration")
        connect = float(connect_value)
        read = float(read_value)
        retry = int(retry_value)
        if connect <= 0 or read <= 0 or retry < 0:
            raise StartupFailure("Invalid timeout or retry configuration")
        path_values = {key: values[key] for key in ("config_dir", "database_path", "log_path", "runtime_dir", "staged_updates_dir")}
        if not all(isinstance(value, (str, Path)) for value in path_values.values()):
            raise StartupFailure("Invalid runtime path")
        def path_value(value: object) -> Path:
            if not isinstance(value, (str, Path)):
                raise StartupFailure("Invalid runtime path")
            return Path(value)
        paths = {key: path_value(value) for key, value in path_values.items()}
        return cls(environment, url, channel, str(values["logging_level"]), **paths,
                   connect_timeout=connect, read_timeout=read, retry_limit=retry)

    def summary(self) -> dict[str, object]:
        return {"environment": self.environment, "platform_url": self.platform_url,
                "release_channel": self.release_channel, "logging_level": self.logging_level,
                "config_dir": str(self.config_dir), "database_path": str(self.database_path),
                "log_path": str(self.log_path), "runtime_dir": str(self.runtime_dir),
                "staged_updates_dir": str(self.staged_updates_dir),
                "connect_timeout": self.connect_timeout, "read_timeout": self.read_timeout,
                "retry_limit": self.retry_limit}


@dataclass(frozen=True)
class HealthReport:
    state: HealthState
    configuration: bool
    storage: bool
    recovery: bool
    updates: bool
    trusted_keys: bool


@dataclass(frozen=True)
class DiagnosticsReport:
    agent_version: str
    protocol_version: str
    schema_version: int
    environment: str
    configuration: dict[str, object]
    trusted_keys: dict[str, object]
    recovery: dict[str, object]
    updates: dict[str, object]
    health: HealthReport
    products: tuple[dict[str, str], ...]


class DiagnosticsService:
    def __init__(self, config: ProductionConfig, *, agent_version: str,
                 protocol_version: str, schema_version: int,
                 trusted_key_ids: list[str], recovery: dict[str, object],
                 updates: dict[str, object], health: HealthReport,
                 products: list[dict[str, str]]):
        self.config, self.agent_version, self.protocol_version = config, agent_version, protocol_version
        self.schema_version, self.trusted_key_ids = schema_version, tuple(sorted(trusted_key_ids))
        self.recovery, self.updates, self.health = dict(recovery), dict(updates), health
        self.products = tuple(dict(product) for product in products)

    def report(self) -> DiagnosticsReport:
        return DiagnosticsReport(self.agent_version, self.protocol_version, self.schema_version,
            self.config.environment, self.config.summary(), {"key_ids": self.trusted_key_ids},
            dict(self.recovery), dict(self.updates), self.health, self.products)


class ShutdownCoordinator:
    def __init__(self):
        self._lock = threading.Lock()
        self._closed = False
        self._cleanups: list[Callable[[], None]] = []

    def register(self, cleanup: Callable[[], None]) -> None:
        with self._lock:
            if self._closed:
                cleanup()
            else:
                self._cleanups.append(cleanup)

    def shutdown(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            cleanups = list(reversed(self._cleanups))
            self._cleanups.clear()
        for cleanup in cleanups:
            cleanup()


class StartupValidator:
    def __init__(self, config: ProductionConfig):
        self.config = config

    def validate(self, trusted_keys: Path | None = None) -> None:
        for path in (self.config.config_dir, self.config.runtime_dir, self.config.staged_updates_dir):
            path.mkdir(parents=True, exist_ok=True)
            if not os.access(path, os.W_OK):
                raise StartupFailure(f"Runtime path is not writable: {path}")
        if trusted_keys is not None and not trusted_keys.is_file():
            raise StartupFailure("Trusted key material is unavailable")

    def validate_permissions(self, trusted_key_dir: Path | None = None) -> None:
        paths = [self.config.config_dir, self.config.runtime_dir,
                 self.config.database_path.parent, self.config.log_path.parent,
                 self.config.staged_updates_dir]
        for path in paths:
            if not path.exists() or not os.access(path, os.R_OK | os.W_OK):
                raise StartupFailure(f"Runtime permission validation failed: {path}")
        if trusted_key_dir is not None:
            if not trusted_key_dir.is_dir() or not os.access(trusted_key_dir, os.R_OK):
                raise StartupFailure("Trusted-key directory is unavailable")
            identifiers: set[str] = set()
            for key_file in trusted_key_dir.iterdir():
                if not key_file.is_file() or key_file.stem in identifiers:
                    raise StartupFailure("Duplicate or invalid trusted key")
                identifiers.add(key_file.stem)
                try:
                    if not key_file.read_text().strip().startswith("-----BEGIN"):
                        raise StartupFailure("Malformed trusted key")
                except OSError as exc:
                    raise StartupFailure("Trusted key is unreadable") from exc

    def health(self, *, storage: bool, recovery: bool, updates: bool, trusted_keys: bool) -> HealthReport:
        checks = [storage, recovery, updates, trusted_keys]
        state = HealthState.HEALTHY if all(checks) else HealthState.DEGRADED if any(checks) else HealthState.UNAVAILABLE
        return HealthReport(state, True, storage, recovery, updates, trusted_keys)


class StartupCoordinator:
    def __init__(self, steps: dict[str, Callable[[], None]]):
        self.steps = steps
        self.execution_enabled = False
        self.order: list[str] = []

    def start(self) -> None:
        required = ("configuration", "paths", "trusted_keys", "database", "recovery",
                    "updates", "diagnostics", "logging", "health")
        try:
            for step in required:
                action = self.steps.get(step)
                if action is None:
                    raise StartupFailure(f"Missing startup step: {step}")
                action()
                self.order.append(step)
            self.execution_enabled = True
        except Exception as exc:
            self.execution_enabled = False
            if isinstance(exc, StartupFailure):
                raise
            raise StartupFailure("Startup validation failed") from exc

    def health(self, *, storage: bool, recovery: bool, updates: bool, trusted_keys: bool) -> HealthReport:
        checks = [storage, recovery, updates, trusted_keys]
        state = HealthState.HEALTHY if all(checks) else HealthState.DEGRADED if any(checks) else HealthState.UNAVAILABLE
        return HealthReport(state, True, storage, recovery, updates, trusted_keys)


def configure_logging(path: Path, level: str = "INFO", max_bytes: int = 5_000_000,
                      backup_count: int = 3) -> logging.Logger:
    logger = logging.getLogger("bke")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    handler = logging.handlers.RotatingFileHandler(path, maxBytes=max_bytes, backupCount=backup_count)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    handler.addFilter(RedactingFilter())
    logger.addHandler(handler)
    return logger


class RedactingFilter(logging.Filter):
    _sensitive = ("token", "password", "secret", "private_key", "signature", "lease")
    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        for marker in self._sensitive:
            if marker in message.lower():
                record.msg = "[REDACTED]"
                record.args = ()
                break
        if not hasattr(record, "event_id"):
            material = f"{record.name}:{record.levelno}:{record.getMessage()}"
            record.event_id = hashlib.sha256(material.encode()).hexdigest()[:32]
        return True
