"""Untrusted, non-authoritative lease metadata persistence."""

from datetime import datetime, timezone

from ..storage.database import Database
from .lease import (
    LeaseMetadata,
    LeaseMetadataCorruptError,
    LeaseMetadataPersistenceError,
)


class LeaseMetadataRepository:
    """Stores diagnostics only; it never verifies or authorizes a lease."""

    def __init__(self, database: Database):
        self.database = database

    def save(self, metadata: LeaseMetadata) -> None:
        try:
            with self.database._lock, self.database.connection:
                self.database.connection.execute(
                    """INSERT INTO lease_metadata
                    (lease_id, product_id, installation_id, device_id, generation,
                     status, issuer, issued_at, expires_at, key_id, last_verified_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(lease_id) DO UPDATE SET product_id=excluded.product_id,
                    installation_id=excluded.installation_id, device_id=excluded.device_id,
                    generation=excluded.generation, status=excluded.status,
                    issuer=excluded.issuer, issued_at=excluded.issued_at,
                    expires_at=excluded.expires_at, key_id=excluded.key_id,
                    last_verified_at=excluded.last_verified_at""",
                    (metadata.lease_id, metadata.product_id, metadata.installation_id,
                     metadata.device_id, metadata.generation, metadata.status,
                     metadata.issuer, metadata.issued_at.isoformat(),
                     metadata.expires_at.isoformat(), metadata.key_id,
                     metadata.verified_at.isoformat()),
                )
        except Exception as exc:
            raise LeaseMetadataPersistenceError("Could not save lease metadata") from exc

    def load(self, lease_id: str) -> LeaseMetadata | None:
        try:
            with self.database._lock:
                row = self.database.connection.execute(
                    "SELECT * FROM lease_metadata WHERE lease_id=?", (lease_id,)
                ).fetchone()
            if row is None:
                return None
            data = dict(row)
            data["issued_at"] = datetime.fromisoformat(data["issued_at"])
            data["expires_at"] = datetime.fromisoformat(data["expires_at"])
            data["verified_at"] = datetime.fromisoformat(data["last_verified_at"])
            data.pop("last_verified_at")
            return LeaseMetadata.model_validate(data)
        except LeaseMetadataPersistenceError:
            raise
        except Exception as exc:
            raise LeaseMetadataCorruptError("Lease metadata is malformed") from exc

    def latest(self, product_id: str, device_id: str) -> LeaseMetadata | None:
        try:
            with self.database._lock:
                row = self.database.connection.execute(
                    "SELECT * FROM lease_metadata WHERE product_id=? AND device_id=? "
                    "ORDER BY generation DESC LIMIT 1", (product_id, device_id)
                ).fetchone()
            return self._row_to_metadata(row) if row is not None else None
        except Exception as exc:
            raise LeaseMetadataCorruptError("Lease metadata is malformed") from exc

    @staticmethod
    def _row_to_metadata(row) -> LeaseMetadata:
        data = dict(row)
        data["issued_at"] = datetime.fromisoformat(data["issued_at"])
        data["expires_at"] = datetime.fromisoformat(data["expires_at"])
        data["verified_at"] = datetime.fromisoformat(data["last_verified_at"])
        data.pop("last_verified_at")
        return LeaseMetadata.model_validate(data)

    def delete(self, lease_id: str) -> None:
        try:
            with self.database._lock, self.database.connection:
                self.database.connection.execute(
                    "DELETE FROM lease_metadata WHERE lease_id=?", (lease_id,)
                )
        except Exception as exc:
            raise LeaseMetadataPersistenceError("Could not delete lease metadata") from exc

    def delete_product(self, product_id: str) -> None:
        try:
            with self.database._lock, self.database.connection:
                self.database.connection.execute(
                    "DELETE FROM lease_metadata WHERE product_id=?", (product_id,)
                )
        except Exception as exc:
            raise LeaseMetadataPersistenceError("Could not delete product lease metadata") from exc

    def clear_expired(self, now: datetime | None = None) -> int:
        moment = now or datetime.now(timezone.utc)
        try:
            with self.database._lock, self.database.connection:
                cursor = self.database.connection.execute(
                    "DELETE FROM lease_metadata WHERE expires_at<=?", (moment.isoformat(),)
                )
                return cursor.rowcount
        except Exception as exc:
            raise LeaseMetadataPersistenceError("Could not clear expired metadata") from exc
