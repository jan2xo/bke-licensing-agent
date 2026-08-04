import sqlite3
from pathlib import Path
from typing import Iterable

from ..config import get_database_path
from .models import DiscoveredProductRecord


CREATE_TABLE_SQL = """
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
"""


class Database:
    def __init__(self, path: Path | None = None):
        self.path = path or get_database_path()
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.initialize()

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def initialize(self) -> None:
        with self.connection:
            self.connection.execute(CREATE_TABLE_SQL)

    def save_discovered_product(self, record: DiscoveredProductRecord) -> None:
        with self.connection:
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
