#!/usr/bin/env python3
"""Seed and verify durable Python -> Gen2 runtime-bridge licensing state."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from bke_licensing_agent.devices.fingerprint import DeviceFingerprint  # noqa: E402
from bke_licensing_agent.runtime import InstalledAgentRuntime  # noqa: E402
from bke_licensing_agent.storage.database import Database  # noqa: E402

PRODUCT_ID = "runtime-bridge-cert"
VERSION = "2.0.0"
INSTALLATION_ID = "runtime-bridge-installation"
LICENSE_ID = "runtime-bridge-license"
LEASE_ID = "runtime-bridge-lease"
KEY_ID = "runtime-bridge-state-key"


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def fixture_paths(data_root: Path) -> tuple[Path, Path, Path]:
    product_root = data_root / "runtime-bridge-product"
    return product_root, product_root / "bke.manifest.json", product_root / "product.exe"


def seed(data_root: Path) -> None:
    data_root.mkdir(parents=True, exist_ok=True)
    os.environ["BKE_AGENT_DATA_DIR"] = str(data_root)

    database = Database(data_root / "agent.db")
    product_root, manifest_path, entry_point = fixture_paths(data_root)
    product_root.mkdir(parents=True, exist_ok=True)
    entry_point.write_bytes(b"BKE runtime bridge durable product fixture\n")
    manifest = {
        "schemaVersion": 1,
        "productId": PRODUCT_ID,
        "displayName": "Runtime Bridge Certification Product",
        "version": VERSION,
        "entryPoint": "product.exe",
        "updateChannel": "stable",
        "minimumAgentVersion": "1.0.0",
        "platform": "windows",
        "architecture": "x64",
    }
    manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    trusted_dir = data_root / "trusted-keys"
    trusted_dir.mkdir(parents=True, exist_ok=True)
    (trusted_dir / f"{KEY_ID}.pem").write_bytes(public_key)

    device_id = DeviceFingerprint().calculate()
    now = datetime.now(timezone.utc)
    lease = {
        "license_id": LICENSE_ID,
        "lease_id": LEASE_ID,
        "generation": 1,
        "server_revision": 1,
        "product_id": PRODUCT_ID,
        "installation_id": INSTALLATION_ID,
        "device_id": device_id,
        "version": VERSION,
        "issuer": "runtime-bridge-certification",
        "issued_at": now.isoformat(),
        "not_before": (now - timedelta(minutes=5)).isoformat(),
        "expires_at": (now + timedelta(days=7)).isoformat(),
        "key_id": KEY_ID,
        "algorithm": "Ed25519",
        "revoked": False,
        "superseded_by": None,
    }
    payload = json.dumps(lease, separators=(",", ":"))
    signature = base64.b64encode(private_key.sign(payload.encode("utf-8"))).decode("ascii")

    with database.connection:
        database.connection.execute("DELETE FROM active_license_bindings WHERE product_id=?", (PRODUCT_ID,))
        database.connection.execute("DELETE FROM verified_licenses WHERE product_id=?", (PRODUCT_ID,))
        database.connection.execute("DELETE FROM discovered_products WHERE product_id=?", (PRODUCT_ID,))
        database.connection.execute(
            """INSERT INTO discovered_products
               (product_id, display_name, version, manifest_path, product_root, entry_point_path, discovered_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                PRODUCT_ID,
                manifest["displayName"],
                VERSION,
                str(manifest_path),
                str(product_root),
                str(entry_point),
                now.isoformat(),
            ),
        )
        database.connection.execute(
            """INSERT INTO verified_licenses VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                LICENSE_ID,
                PRODUCT_ID,
                VERSION,
                INSTALLATION_ID,
                device_id,
                LEASE_ID,
                1,
                1,
                lease["issued_at"],
                lease["not_before"],
                lease["expires_at"],
                "verified",
                KEY_ID,
                now.isoformat(),
                now.isoformat(),
                payload,
                signature,
                "Ed25519",
            ),
        )
        database.connection.execute(
            """INSERT INTO active_license_bindings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                PRODUCT_ID,
                INSTALLATION_ID,
                device_id,
                LICENSE_ID,
                LEASE_ID,
                1,
                1,
                1,
                now.isoformat(),
            ),
        )
    database.close()
    print(f"Seeded durable runtime-bridge state for device {device_id}")


def read_state(data_root: Path) -> dict[str, object]:
    database_path = data_root / "agent.db"
    if not database_path.is_file():
        raise RuntimeError(f"Agent database missing: {database_path}")

    connection = sqlite3.connect(database_path)
    try:
        schema = connection.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
        product = connection.execute(
            """SELECT product_id, display_name, version, manifest_path, product_root, entry_point_path
               FROM discovered_products WHERE product_id=? AND version=?""",
            (PRODUCT_ID, VERSION),
        ).fetchone()
        license_row = connection.execute(
            """SELECT license_id, product_id, product_version, installation_id, device_id, lease_id,
                      generation, server_revision, issued_at, not_before, expires_at, status, key_id,
                      signed_payload, signed_signature, signed_algorithm
               FROM verified_licenses WHERE license_id=?""",
            (LICENSE_ID,),
        ).fetchone()
        binding = connection.execute(
            """SELECT product_id, installation_id, device_id, active_license_id, active_lease_id,
                      generation, server_revision, binding_version
               FROM active_license_bindings WHERE product_id=? AND installation_id=?""",
            (PRODUCT_ID, INSTALLATION_ID),
        ).fetchone()
    finally:
        connection.close()

    product_root, manifest_path, entry_point = fixture_paths(data_root)
    trusted_key = data_root / "trusted-keys" / f"{KEY_ID}.pem"
    for required in (manifest_path, entry_point, trusted_key):
        if not required.is_file():
            raise RuntimeError(f"Durable fixture file missing: {required}")

    if schema is None or product is None or license_row is None or binding is None:
        raise RuntimeError("Durable runtime-bridge authority rows are incomplete")

    return {
        "schema_version": schema[0],
        "product": list(product),
        "license": list(license_row),
        "binding": list(binding),
        "manifest_sha256": sha256_bytes(manifest_path.read_bytes()),
        "entry_point_sha256": sha256_bytes(entry_point.read_bytes()),
        "trusted_key_sha256": sha256_bytes(trusted_key.read_bytes()),
        "device_id": binding[2],
        "product_root": str(product_root),
    }



def prove_python_authorization(data_root: Path) -> None:
    os.environ["BKE_AGENT_DATA_DIR"] = str(data_root)
    database = Database(data_root / "agent.db")
    runtime = InstalledAgentRuntime(database=database, port=43873, module_server=object())  # type: ignore[arg-type]
    try:
        result = runtime.authorize({
            "product_id": PRODUCT_ID,
            "version": VERSION,
            "installation_id": INSTALLATION_ID,
        })
    finally:
        database.close()
    if result.get("authorized") is not True or result.get("reason") != "authorized":
        raise SystemExit(f"Canonical Python authorization failed before migration: {result}")
    print("Canonical Python durable-state authorization: PASS")

def write_snapshot(data_root: Path, snapshot_path: Path) -> None:
    state = read_state(data_root)
    snapshot_path.parent.mkdir(parents=True, exist_ok=True)
    snapshot_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Frozen durable authority snapshot: {snapshot_path}")
    print(f"Frozen device id: {state['device_id']}")


def assert_snapshot(data_root: Path, snapshot_path: Path) -> None:
    expected = json.loads(snapshot_path.read_text(encoding="utf-8"))
    actual = read_state(data_root)
    if actual != expected:
        print("EXPECTED:")
        print(json.dumps(expected, indent=2, sort_keys=True))
        print("ACTUAL:")
        print(json.dumps(actual, indent=2, sort_keys=True))
        raise SystemExit("Durable Agent licensing/trust state changed during runtime migration")
    print("Durable Agent licensing/trust state preserved: PASS")
    print(f"Preserved device id: {actual['device_id']}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("seed", "snapshot", "assert"))
    parser.add_argument("--data-root", required=True, type=Path)
    parser.add_argument("--snapshot", required=True, type=Path)
    args = parser.parse_args()

    if args.command == "seed":
        seed(args.data_root)
        prove_python_authorization(args.data_root)
        write_snapshot(args.data_root, args.snapshot)
    elif args.command == "snapshot":
        write_snapshot(args.data_root, args.snapshot)
    else:
        assert_snapshot(args.data_root, args.snapshot)


if __name__ == "__main__":
    main()
