"""Multi-license repository and active-license binding persistence."""

from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field

from ..storage.database import Database
from .lease import LicenseLease


class VerifiedLicenseRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    license_id: str = Field(min_length=1)
    product_id: str = Field(min_length=1)
    product_version: str = Field(min_length=1)
    installation_id: str = Field(min_length=1)
    device_id: str = Field(min_length=1)
    lease_id: str = Field(min_length=1)
    generation: int = Field(ge=0)
    server_revision: int = Field(ge=0)
    issued_at: datetime
    not_before: datetime
    expires_at: datetime
    status: str = Field(min_length=1)
    key_id: str = Field(min_length=1)
    created_at: datetime
    updated_at: datetime


class ActiveLicenseBinding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    product_id: str
    installation_id: str
    device_id: str
    active_license_id: str
    active_lease_id: str
    generation: int = Field(ge=0)
    server_revision: int = Field(ge=0)
    binding_version: int = Field(ge=0)
    updated_at: datetime


class LicenseRepositoryError(Exception):
    """Base persistence error."""


class LicenseRecordCorruptError(LicenseRepositoryError): pass
class LicenseRecordPersistenceError(LicenseRepositoryError): pass


class VerifiedLicenseRepository:
    def __init__(self, database: Database):
        self.database = database

    def save(self, record: VerifiedLicenseRecord) -> None:
        now = datetime.now(timezone.utc).isoformat()
        try:
            with self.database._lock, self.database.connection:
                self.database.connection.execute(
                    """INSERT INTO verified_licenses VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(lease_id) DO UPDATE SET license_id=excluded.license_id,
                    product_version=excluded.product_version,
                    status=excluded.status, updated_at=excluded.updated_at""",
                    (record.license_id, record.product_id, record.product_version,
                     record.installation_id, record.device_id, record.lease_id,
                     record.generation, record.server_revision, record.issued_at.isoformat(),
                     record.not_before.isoformat(), record.expires_at.isoformat(), record.status,
                     record.key_id, record.created_at.isoformat(), now),
                )
        except Exception as exc:
            raise LicenseRecordPersistenceError("Could not save verified license") from exc

    def load(self, license_id: str) -> VerifiedLicenseRecord | None:
        try:
            with self.database._lock:
                row = self.database.connection.execute(
                    "SELECT * FROM verified_licenses WHERE license_id=? ORDER BY updated_at DESC LIMIT 1", (license_id,)
                ).fetchone()
            return self._record(row) if row else None
        except LicenseRepositoryError:
            raise
        except Exception as exc:
            raise LicenseRecordCorruptError("Verified license record is corrupt") from exc

    def list_for_product(self, product_id: str) -> list[VerifiedLicenseRecord]:
        with self.database._lock:
            rows = self.database.connection.execute(
                "SELECT * FROM verified_licenses WHERE product_id=? ORDER BY updated_at DESC", (product_id,)
            ).fetchall()
        return [self._record(row) for row in rows]

    def load_lease(self, lease_id: str) -> VerifiedLicenseRecord | None:
        with self.database._lock:
            row = self.database.connection.execute(
                "SELECT * FROM verified_licenses WHERE lease_id=?", (lease_id,)
            ).fetchone()
        return self._record(row) if row else None

    def bind(self, binding: ActiveLicenseBinding) -> None:
        try:
            with self.database._lock, self.database.connection:
                exists = self.database.connection.execute(
                    "SELECT 1 FROM verified_licenses WHERE license_id=?", (binding.active_license_id,)
                ).fetchone()
                if exists is None:
                    raise LicenseRecordCorruptError("Active binding references missing license")
                self.database.connection.execute(
                    """INSERT INTO active_license_bindings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(product_id, installation_id, device_id) DO UPDATE SET
                    active_license_id=excluded.active_license_id, active_lease_id=excluded.active_lease_id,
                    generation=excluded.generation, server_revision=excluded.server_revision,
                    binding_version=excluded.binding_version, updated_at=excluded.updated_at""",
                    (binding.product_id, binding.installation_id, binding.device_id,
                     binding.active_license_id, binding.active_lease_id, binding.generation,
                     binding.server_revision, binding.binding_version, binding.updated_at.isoformat()),
                )
        except LicenseRepositoryError:
            raise
        except Exception as exc:
            raise LicenseRecordPersistenceError("Could not bind active license") from exc

    def migrate_legacy_metadata(self) -> int:
        """Copy verified legacy metadata once; legacy rows remain diagnostic."""
        now = datetime.now(timezone.utc)
        migrated = 0
        try:
            with self.database._lock, self.database.connection:
                rows = self.database.connection.execute(
                    "SELECT * FROM lease_metadata WHERE status='verified'"
                ).fetchall()
                for row in rows:
                    license_id = f"legacy-{row['lease_id']}"
                    exists = self.database.connection.execute(
                        "SELECT 1 FROM verified_licenses WHERE license_id=?", (license_id,)
                    ).fetchone()
                    if exists:
                        continue
                    self.database.connection.execute(
                        """INSERT INTO verified_licenses VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (license_id, row['product_id'], "unknown", row['installation_id'],
                         row['device_id'], row['lease_id'], row['generation'],
                         row['server_revision'], row['issued_at'], row['issued_at'],
                         row['expires_at'], row['status'], row['key_id'], now.isoformat(), now.isoformat()),
                    )
                    self.database.connection.execute(
                        """INSERT OR IGNORE INTO active_license_bindings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (row['product_id'], row['installation_id'], row['device_id'], license_id,
                         row['lease_id'], row['generation'], row['server_revision'], 1, now.isoformat()),
                    )
                    migrated += 1
            return migrated
        except Exception as exc:
            raise LicenseRecordPersistenceError("Legacy license migration failed") from exc

    def active(self, product_id: str, installation_id: str, device_id: str) -> ActiveLicenseBinding | None:
        with self.database._lock:
            row = self.database.connection.execute(
                "SELECT * FROM active_license_bindings WHERE product_id=? AND installation_id=? AND device_id=?",
                (product_id, installation_id, device_id),
            ).fetchone()
        if row is None:
            return None
        try:
            return ActiveLicenseBinding.model_validate(dict(row))
        except Exception as exc:
            raise LicenseRecordCorruptError("Active license binding is corrupt") from exc

    def active_verified_license(self, product_id: str, installation_id: str,
                                device_id: str) -> VerifiedLicenseRecord | None:
        binding = self.active(product_id, installation_id, device_id)
        if binding is None:
            return None
        record = self.load(binding.active_license_id)
        if record is None:
            raise LicenseRecordCorruptError("Active binding references missing license")
        if (record.license_id != binding.active_license_id or
                record.product_id != binding.product_id or
                record.installation_id != binding.installation_id or
                record.device_id != binding.device_id or
                record.lease_id != binding.active_lease_id or
                record.generation != binding.generation or
                record.server_revision != binding.server_revision):
            raise LicenseRecordCorruptError("Active binding does not match license")
        return record

    @staticmethod
    def _record(row) -> VerifiedLicenseRecord:
        data = dict(row)
        for field in ("issued_at", "not_before", "expires_at", "created_at", "updated_at"):
            data[field] = datetime.fromisoformat(data[field])
        return VerifiedLicenseRecord.model_validate(data)
