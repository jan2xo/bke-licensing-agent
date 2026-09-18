#!/usr/bin/env python3
"""Seed signed Air Stack and Render Dock authority for installed Gen2 compatibility certification."""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from bke_licensing_agent.devices.fingerprint import DeviceFingerprint  # noqa: E402
from bke_licensing_agent.storage.database import Database  # noqa: E402

KEY_ID = "runtime-bridge-real-products"
AIR_INSTALLATION_ID = "11111111-1111-4111-8111-111111111111"
RENDER_INSTALLATION_ID = "22222222-2222-4222-8222-222222222222"

EXPECTED = (
    {
        "product_id": "bke-air-stack",
        "display_name": "Air Stack",
        "version": "1.0.0",
        "entry_point": "BKE AirStack.exe",
        "installation_id": AIR_INSTALLATION_ID,
        "license_id": "runtime-bridge-air-stack-license",
        "lease_id": "runtime-bridge-air-stack-lease",
    },
    {
        "product_id": "bke-render-dock",
        "display_name": "Render Dock",
        "version": "1.0.2",
        "entry_point": "RENDER DOCK.exe",
        "installation_id": RENDER_INSTALLATION_ID,
        "license_id": "runtime-bridge-render-dock-license",
        "lease_id": "runtime-bridge-render-dock-lease",
    },
)


def load_product(product_root: Path, expected: dict[str, str]) -> tuple[dict[str, object], Path, Path]:
    manifest_path = product_root / "bke.manifest.json"
    if not manifest_path.is_file():
        raise RuntimeError(f"Product manifest missing: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    for key, expected_value in (
        ("productId", expected["product_id"]),
        ("displayName", expected["display_name"]),
        ("version", expected["version"]),
        ("entryPoint", expected["entry_point"]),
    ):
        if manifest.get(key) != expected_value:
            raise RuntimeError(
                f"{expected['product_id']} manifest {key} drift: {manifest.get(key)!r} != {expected_value!r}"
            )
    if manifest.get("schemaVersion") != 1:
        raise RuntimeError(f"{expected['product_id']} manifest schema drift")
    entry_point = product_root / expected["entry_point"]
    if not entry_point.is_file():
        raise RuntimeError(f"Product entry point missing: {entry_point}")
    return manifest, manifest_path, entry_point


def seed_product(
    database: Database,
    *,
    expected: dict[str, str],
    product_root: Path,
    manifest: dict[str, object],
    manifest_path: Path,
    entry_point: Path,
    private_key: Ed25519PrivateKey,
    device_id: str,
    now: datetime,
) -> None:
    lease = {
        "license_id": expected["license_id"],
        "lease_id": expected["lease_id"],
        "generation": 1,
        "server_revision": 1,
        "product_id": expected["product_id"],
        "installation_id": expected["installation_id"],
        "device_id": device_id,
        "version": expected["version"],
        "issuer": "runtime-bridge-real-product-certification",
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
        database.connection.execute(
            "DELETE FROM active_license_bindings WHERE product_id=?",
            (expected["product_id"],),
        )
        database.connection.execute(
            "DELETE FROM verified_licenses WHERE product_id=?",
            (expected["product_id"],),
        )
        database.connection.execute(
            "DELETE FROM discovered_products WHERE product_id=?",
            (expected["product_id"],),
        )
        database.connection.execute(
            """INSERT INTO discovered_products
               (product_id, display_name, version, manifest_path, product_root, entry_point_path, discovered_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                expected["product_id"],
                expected["display_name"],
                expected["version"],
                str(manifest_path),
                str(product_root),
                str(entry_point),
                now.isoformat(),
            ),
        )
        database.connection.execute(
            """INSERT INTO verified_licenses VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                expected["license_id"],
                expected["product_id"],
                expected["version"],
                expected["installation_id"],
                device_id,
                expected["lease_id"],
                1,
                1,
                now.isoformat(),
                (now - timedelta(minutes=5)).isoformat(),
                (now + timedelta(days=7)).isoformat(),
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
                expected["product_id"],
                expected["installation_id"],
                device_id,
                expected["license_id"],
                expected["lease_id"],
                1,
                1,
                1,
                now.isoformat(),
            ),
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-root", required=True, type=Path)
    parser.add_argument("--air-root", required=True, type=Path)
    parser.add_argument("--render-root", required=True, type=Path)
    args = parser.parse_args()

    os.environ["BKE_AGENT_DATA_DIR"] = str(args.data_root)
    products = (
        (args.air_root.resolve(), EXPECTED[0]),
        (args.render_root.resolve(), EXPECTED[1]),
    )

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    trusted_dir = args.data_root / "trusted-keys"
    trusted_dir.mkdir(parents=True, exist_ok=True)
    (trusted_dir / f"{KEY_ID}.pem").write_bytes(public_key)

    device_id = DeviceFingerprint().calculate()
    database = Database(args.data_root / "agent.db")
    now = datetime.now(timezone.utc)
    try:
        for product_root, expected in products:
            manifest, manifest_path, entry_point = load_product(product_root, expected)
            seed_product(
                database,
                expected=expected,
                product_root=product_root,
                manifest=manifest,
                manifest_path=manifest_path,
                entry_point=entry_point,
                private_key=private_key,
                device_id=device_id,
                now=now,
            )
            print(
                f"Seeded {expected['product_id']} {expected['version']} "
                f"for installation {expected['installation_id']}"
            )
    finally:
        database.close()

    print(f"Real-product runtime-bridge device id: {device_id}")


if __name__ == "__main__":
    main()
