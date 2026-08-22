import sqlite3
import threading
from pathlib import Path
from collections.abc import Callable

from ..config import get_database_path
from .models import DiscoveredProductRecord

CURRENT_SCHEMA_VERSION = 7


MIGRATIONS: dict[int, tuple[str, ...]] = {
    1: ("""
CREATE TABLE IF NOT EXISTS discovered_products (
    product_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    version TEXT NOT NULL,
    manifest_path TEXT NOT NULL,
    product_root TEXT NOT NULL,
    entry_point_path TEXT NOT NULL,
    discovered_at TEXT NOT NULL,
    PRIMARY KEY (manifest_path)
)
""", """
CREATE TABLE IF NOT EXISTS activation_cache (
    product_id TEXT NOT NULL, license_id TEXT NOT NULL, device_id TEXT NOT NULL,
    activation_id TEXT NOT NULL, status TEXT NOT NULL, updated_at TEXT NOT NULL,
    PRIMARY KEY (product_id, device_id)
)
"""),
    2: ("""
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, event_type TEXT NOT NULL,
    product_id TEXT, device_id TEXT, activation_id TEXT,
    result TEXT NOT NULL, created_at TEXT NOT NULL
)
""",),
    3: ("""
CREATE TABLE IF NOT EXISTS lease_metadata (
    lease_id TEXT PRIMARY KEY,
    product_id TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    status TEXT NOT NULL,
    issuer TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    key_id TEXT NOT NULL,
    last_verified_at TEXT NOT NULL
)
""",),
    4: ("ALTER TABLE lease_metadata ADD COLUMN server_revision INTEGER NOT NULL DEFAULT 0",),
    5: ("""
CREATE TABLE IF NOT EXISTS verified_licenses (
    license_id TEXT PRIMARY KEY,
    product_id TEXT NOT NULL,
    product_version TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    lease_id TEXT NOT NULL UNIQUE,
    generation INTEGER NOT NULL,
    server_revision INTEGER NOT NULL,
    issued_at TEXT NOT NULL,
    not_before TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    status TEXT NOT NULL,
    key_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
)
""", """
CREATE TABLE IF NOT EXISTS active_license_bindings (
    product_id TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    active_license_id TEXT NOT NULL,
    active_lease_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    server_revision INTEGER NOT NULL,
    binding_version INTEGER NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (product_id, installation_id, device_id),
    FOREIGN KEY (active_license_id) REFERENCES verified_licenses(license_id)
)
"""),
    6: ("""
CREATE TABLE verified_licenses_v6 (
    license_id TEXT NOT NULL,
    product_id TEXT NOT NULL,
    product_version TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    lease_id TEXT PRIMARY KEY,
    generation INTEGER NOT NULL,
    server_revision INTEGER NOT NULL,
    issued_at TEXT NOT NULL,
    not_before TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    status TEXT NOT NULL,
    key_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
)
""", """
INSERT INTO verified_licenses_v6 SELECT license_id, product_id, product_version,
installation_id, device_id, lease_id, generation, server_revision, issued_at,
not_before, expires_at, status, key_id, created_at, updated_at
FROM verified_licenses
""", """
ALTER TABLE active_license_bindings RENAME TO active_license_bindings_v6
""", """
CREATE TABLE active_license_bindings (
    product_id TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    active_license_id TEXT NOT NULL,
    active_lease_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    server_revision INTEGER NOT NULL,
    binding_version INTEGER NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (product_id, installation_id, device_id)
)
""", """
INSERT INTO active_license_bindings SELECT * FROM active_license_bindings_v6
""", """
DROP TABLE active_license_bindings_v6
""", """
DROP TABLE verified_licenses
""", """
ALTER TABLE verified_licenses_v6 RENAME TO verified_licenses
"""),
    7: ("""
CREATE TABLE verified_licenses_v7 (
    license_id TEXT NOT NULL,
    product_id TEXT NOT NULL,
    product_version TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    lease_id TEXT PRIMARY KEY,
    generation INTEGER NOT NULL,
    server_revision INTEGER NOT NULL,
    issued_at TEXT NOT NULL,
    not_before TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    status TEXT NOT NULL,
    key_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    signed_payload TEXT,
    signed_signature TEXT,
    signed_algorithm TEXT
)
""", """
INSERT INTO verified_licenses_v7
SELECT license_id, product_id, product_version, installation_id, device_id,
lease_id, generation, server_revision, issued_at, not_before, expires_at,
status, key_id, created_at, updated_at, NULL, NULL, NULL
FROM verified_licenses
""", """
DROP TABLE verified_licenses
""", """
ALTER TABLE verified_licenses_v7 RENAME TO verified_licenses
"""),
}


class Database:
    def __init__(self, path: Path | None = None,
                 migration_hook: Callable[[int], None] | None = None):
        self.path = path or get_database_path()
        self.connection = sqlite3.connect(self.path, check_same_thread=False)
        self._lock = threading.RLock()
        self.connection.row_factory = sqlite3.Row
        try:
            self.initialize(migration_hook=migration_hook)
        except Exception:
            self.connection.close()
            raise

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def initialize(self, migration_hook: Callable[[int], None] | None = None) -> None:
        self.connection.execute("BEGIN")
        try:
            self.connection.execute(
                "CREATE TABLE IF NOT EXISTS schema_version "
                "(version INTEGER NOT NULL)"
            )
            if self.connection.execute("SELECT COUNT(*) FROM schema_version").fetchone()[0] == 0:
                self.connection.execute("INSERT INTO schema_version (version) VALUES (0)")
            version = self.connection.execute(
                "SELECT version FROM schema_version"
            ).fetchone()[0]
            if version > CURRENT_SCHEMA_VERSION:
                raise RuntimeError("Database schema is newer than this agent supports")
            for target in range(version + 1, CURRENT_SCHEMA_VERSION + 1):
                for statement in MIGRATIONS[target]:
                    self.connection.execute(statement)
                if migration_hook:
                    migration_hook(target)
                self.connection.execute("UPDATE schema_version SET version=?", (target,))
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise

    def save_activation(self, product_id: str, license_id: str, device_id: str, activation_id: str, status: str) -> None:
        from datetime import datetime, timezone
        with self._lock, self.connection:
            self.connection.execute("""INSERT INTO activation_cache
                (product_id, license_id, device_id, activation_id, status, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(product_id, device_id) DO UPDATE SET license_id=excluded.license_id,
                activation_id=excluded.activation_id, status=excluded.status, updated_at=excluded.updated_at""",
                (product_id, license_id, device_id, activation_id, status, datetime.now(timezone.utc).isoformat()))

    def update_activation_status(self, product_id: str, device_id: str, status: str) -> None:
        with self._lock, self.connection:
            self.connection.execute("UPDATE activation_cache SET status=?, updated_at=? WHERE product_id=? AND device_id=?",
                (status, __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(), product_id, device_id))

    def invalidate_activation(self, product_id: str, device_id: str, status: str) -> None:
        self.update_activation_status(product_id, device_id, status)

    def record_audit_event(self, event_type: str, result: str, product_id: str | None = None,
                           device_id: str | None = None, activation_id: str | None = None) -> None:
        from datetime import datetime, timezone
        with self._lock, self.connection:
            self.connection.execute("""INSERT INTO audit_events
                (event_type, product_id, device_id, activation_id, result, created_at)
                VALUES (?, ?, ?, ?, ?, ?)""", (event_type, product_id, device_id,
                activation_id, result, datetime.now(timezone.utc).isoformat()))

    def list_audit_events(self) -> list[dict]:
        cursor = self.connection.execute("SELECT * FROM audit_events ORDER BY id")
        return [dict(row) for row in cursor.fetchall()]

    def save_discovered_product(self, record: DiscoveredProductRecord) -> None:
        with self._lock, self.connection:
            self.connection.execute(
                """
                INSERT OR REPLACE INTO discovered_products (
                    product_id,
                    display_name,
                    version,
                    manifest_path,
                    product_root,
                    entry_point_path,
                    discovered_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.product_id,
                    record.display_name,
                    record.version,
                    record.manifest_path,
                    record.product_root,
                    record.entry_point_path,
                    record.discovered_at,
                ),
            )

    def list_discovered_products(self) -> list[DiscoveredProductRecord]:
        cursor = self.connection.execute(
            "SELECT * FROM discovered_products ORDER BY discovered_at DESC"
        )
        return [DiscoveredProductRecord.from_row(dict(row)) for row in cursor.fetchall()]

    def delete_discovered_product(self, manifest_path: str) -> None:
        with self._lock, self.connection:
            self.connection.execute(
                "DELETE FROM discovered_products WHERE manifest_path = ?",
                (manifest_path,),
            )
