#!/usr/bin/env python3
"""Generation 1 Python oracle -> Gen2 machine-readable inventory differential checks."""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path

from bke_licensing_agent import local_api, notification_local_api
from bke_licensing_agent.storage.database import CURRENT_SCHEMA_VERSION, Database

ROOT = Path(__file__).resolve().parents[2]
INVENTORY = ROOT / "dotnet" / "contracts" / "gen1-baseline.json"
PYTHON_LOCAL_API = ROOT / "src" / "bke_licensing_agent" / "local_api.py"
PYTHON_NOTIFICATION_API = ROOT / "src" / "bke_licensing_agent" / "notification_local_api.py"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"DIFFERENTIAL FAIL: {message}")


def main() -> None:
    inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
    local = inventory["local_api"]
    caps = inventory["capabilities"]

    require(
        inventory["python_oracle"]["commit"]
        == "77bdcd0be364192a6c1adea073659c4a462ce0e7",
        "frozen Python oracle SHA changed",
    )
    require(local_api.MAX_JSON_BODY_BYTES == local["max_json_body_bytes"], "JSON body limit differs")
    require(local_api.MAX_CHUNK_LINE_BYTES == local["max_chunk_line_bytes"], "chunk line limit differs")
    require(local_api.UPDATE_CAPABILITY_ID == caps["updates"]["capability_id"], "update capability differs")
    require(local_api.UPDATE_CONTRACT_VERSION == caps["updates"]["contract_version"], "update contract version differs")
    require(local_api.NOTIFICATION_CAPABILITY_ID == caps["typed_notifications"]["capability_id"], "typed-notification capability differs")
    require(local_api.NOTIFICATION_CONTRACT_VERSION == caps["typed_notifications"]["contract_version"], "typed-notification contract version differs")
    require(
        notification_local_api.NOTIFICATION_INBOX_CAPABILITY_ID
        == caps["notification_inbox"]["capability_id"],
        "notification inbox capability differs",
    )
    require(
        notification_local_api.NOTIFICATION_INBOX_CONTRACT_VERSION
        == caps["notification_inbox"]["contract_version"],
        "notification inbox contract version differs",
    )
    require(CURRENT_SCHEMA_VERSION == inventory["storage"]["schema_version"] == 8, "SQLite schema version differs")

    route_literals: set[str] = set()
    for path in (PYTHON_LOCAL_API, PYTHON_NOTIFICATION_API):
        source = path.read_text(encoding="utf-8")
        route_literals.update(re.findall(r'["\'](/(?:license-center|v1/[^"\']+))["\']', source))

    inventory_paths = {route["path"] for route in local["routes"]}
    require(
        inventory_paths <= route_literals,
        f"inventory contains route not present in Python source: {sorted(inventory_paths - route_literals)}",
    )

    with tempfile.TemporaryDirectory() as directory:
        db_path = Path(directory) / "agent.db"
        with Database(db_path) as database:
            version = database.connection.execute("SELECT version FROM schema_version").fetchone()[0]
            require(version == 8, "disposable Python DB did not initialize at schema 8")
            actual_tables = {
                row[0]
                for row in database.connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                ).fetchall()
            }
            for table, expected_columns in inventory["storage"]["tables"].items():
                require(table in actual_tables, f"missing Python table {table}")
                actual_columns = {
                    row[1]
                    for row in database.connection.execute(f"PRAGMA table_info({table})").fetchall()
                }
                require(
                    actual_columns == set(expected_columns),
                    f"column drift in {table}: {sorted(actual_columns)}",
                )

            notification_columns = {
                row[1]
                for row in database.connection.execute("PRAGMA table_info(notifications)").fetchall()
            }
            require("delivery_mode" not in notification_columns, "EVERY_LAUNCH leaked into schema 8")

    print("BKE Licensing Agent Python -> Gen2 inventory differential: PASS")
    print(f"Routes inventoried: {len(inventory_paths)}")
    print(f"SQLite schema: {CURRENT_SCHEMA_VERSION}")


if __name__ == "__main__":
    main()
