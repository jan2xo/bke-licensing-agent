#!/usr/bin/env python3
"""Differential certification for the first real Gen2 capability: authorization."""

from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from bke_licensing_agent.devices.fingerprint import DeviceFingerprint  # noqa: E402
from bke_licensing_agent.runtime import InstalledAgentRuntime  # noqa: E402
from bke_licensing_agent.storage.database import Database  # noqa: E402

PRODUCT_ID = "gen2-auth-demo"
VERSION = "1.0.0"
INSTALLATION_ID = "installation-gen2-1"
LICENSE_ID = "license-gen2-1"
LEASE_ID = "lease-gen2-1"
KEY_ID = "gen2-test-key"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class _ServerUrl:
    def __init__(self, port: int):
        self.port = port

    def license_center_url(self, product_id: str, version: str, installation_id: str) -> str:
        from urllib.parse import urlencode
        return f"http://127.0.0.1:{self.port}/license-center?{urlencode({
            'product_id': product_id,
            'version': version,
            'installation_id': installation_id,
        })}"


def request_dotnet(port: int, body: dict[str, str]) -> dict[str, object]:
    payload = json.dumps(body, separators=(",", ":")).encode()
    request = Request(
        f"http://127.0.0.1:{port}/v1/authorize",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=5) as response:
        assert response.status == 200, response.status
        return json.loads(response.read())


def wait_for_host(port: int, process: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate(timeout=2)
            raise RuntimeError(f"Gen2 host exited early\nstdout:\n{stdout}\nstderr:\n{stderr}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("Gen2 host did not start")


def normalize(result: dict[str, object]) -> dict[str, object]:
    return {key: result[key] for key in ("authorized", "reason", "license_center_url") if key in result}


def assert_parity(runtime: InstalledAgentRuntime, port: int, body: dict[str, str], label: str) -> None:
    python_result = normalize(runtime.authorize(body))
    dotnet_result = normalize(request_dotnet(port, body))
    if python_result != dotnet_result:
        raise AssertionError(
            f"{label} drifted\nPython: {json.dumps(python_result, sort_keys=True)}\n"
            f".NET:   {json.dumps(dotnet_result, sort_keys=True)}"
        )
    print(f"PASS {label}: {python_result['reason']}")


def write_manifest(root: Path, database: Database) -> None:
    product_root = root / "product"
    product_root.mkdir(parents=True)
    entry_point = product_root / "app.bin"
    entry_point.write_bytes(b"gen2")
    manifest_path = product_root / "bke.manifest.json"
    manifest = {
        "schemaVersion": 1,
        "productId": PRODUCT_ID,
        "displayName": "Gen2 Authorization Demo",
        "version": VERSION,
        "entryPoint": "app.bin",
        "updateChannel": "stable",
        "minimumAgentVersion": "1.0.0",
        "platform": "linux" if sys.platform.startswith("linux") else ("windows" if os.name == "nt" else "macos"),
        "architecture": "x64",
    }
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with database.connection:
        database.connection.execute(
            """INSERT INTO discovered_products
               (product_id, display_name, version, manifest_path, product_root, entry_point_path, discovered_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (PRODUCT_ID, manifest["displayName"], VERSION, str(manifest_path), str(product_root),
             str(entry_point), datetime.now(timezone.utc).isoformat()),
        )


def signed_fixture(database: Database, root: Path) -> tuple[Ed25519PrivateKey, dict[str, object]]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    device_id = DeviceFingerprint().calculate()
    now = datetime.now(timezone.utc)
    lease = {
        "license_id": LICENSE_ID,
        "lease_id": LEASE_ID,
        "generation": 1,
        "server_revision": 7,
        "product_id": PRODUCT_ID,
        "installation_id": INSTALLATION_ID,
        "device_id": device_id,
        "version": VERSION,
        "issuer": "gen2-certification",
        "issued_at": now.isoformat(),
        "not_before": (now - timedelta(minutes=5)).isoformat(),
        "expires_at": (now + timedelta(days=1)).isoformat(),
        "key_id": KEY_ID,
        "algorithm": "Ed25519",
        "revoked": False,
        "superseded_by": None,
    }
    payload = json.dumps(lease, separators=(",", ":"))
    signature = base64.b64encode(private_key.sign(payload.encode())).decode()
    with database.connection:
        database.connection.execute(
            """INSERT INTO verified_licenses VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (LICENSE_ID, PRODUCT_ID, VERSION, INSTALLATION_ID, device_id, LEASE_ID, 1, 7,
             lease["issued_at"], lease["not_before"], lease["expires_at"], "verified", KEY_ID,
             now.isoformat(), now.isoformat(), payload, signature, "Ed25519"),
        )
        database.connection.execute(
            """INSERT INTO active_license_bindings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (PRODUCT_ID, INSTALLATION_ID, device_id, LICENSE_ID, LEASE_ID, 1, 7, 1, now.isoformat()),
        )
    (root / "trusted-keys").mkdir(exist_ok=True)
    return private_key, {"payload": payload, "signature": signature, "public_key": public_key, "lease": lease}


def update_signed_lease(database: Database, private_key: Ed25519PrivateKey, lease: dict[str, object]) -> None:
    payload = json.dumps(lease, separators=(",", ":"))
    signature = base64.b64encode(private_key.sign(payload.encode())).decode()
    with database.connection:
        database.connection.execute(
            """UPDATE verified_licenses
               SET issued_at=?, not_before=?, expires_at=?, signed_payload=?, signed_signature=?
               WHERE lease_id=?""",
            (lease["issued_at"], lease["not_before"], lease["expires_at"], payload, signature, LEASE_ID),
        )


def main() -> None:
    host_dll = ROOT / "dotnet" / "src" / "BKE.LicensingAgent.Host" / "bin" / "Release" / "net10.0" / "BKE.LicensingAgent.Host.dll"
    if not host_dll.exists():
        raise RuntimeError(f"Build Gen2 host first: {host_dll}")

    with tempfile.TemporaryDirectory(prefix="bke-gen2-auth-") as temp:
        data_dir = Path(temp)
        os.environ["BKE_AGENT_DATA_DIR"] = str(data_dir)
        port = free_port()
        os.environ["BKE_AGENT_PORT"] = str(port)

        database = Database(data_dir / "agent.db")
        write_manifest(data_dir, database)
        runtime = InstalledAgentRuntime(database=database, port=port)
        runtime._server = _ServerUrl(port)  # type: ignore[assignment]

        env = os.environ.copy()
        env["BKE_AGENT_VNEXT_ENABLE"] = "1"
        process = subprocess.Popen(
            ["dotnet", str(host_dll)], cwd=ROOT, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        try:
            wait_for_host(port, process)
            assert_parity(
                runtime, port,
                {"product_id": "missing-product", "version": VERSION, "installation_id": INSTALLATION_ID},
                "unknown product/version",
            )
            request = {"product_id": PRODUCT_ID, "version": VERSION, "installation_id": INSTALLATION_ID}
            assert_parity(runtime, port, request, "activation required")

            private_key, fixture = signed_fixture(database, data_dir)
            assert_parity(runtime, port, request, "trusted keys unavailable")

            (data_dir / "trusted-keys" / f"{KEY_ID}.pem").write_text(str(fixture["public_key"]), encoding="utf-8")
            assert_parity(runtime, port, request, "verified signed lease")

            with database.connection:
                database.connection.execute(
                    "UPDATE verified_licenses SET signed_signature=? WHERE lease_id=?",
                    (base64.b64encode(b"x" * 64).decode(), LEASE_ID),
                )
            assert_parity(runtime, port, request, "invalid signature fails closed")

            lease = dict(fixture["lease"])
            now = datetime.now(timezone.utc)
            lease["issued_at"] = (now - timedelta(days=3)).isoformat()
            lease["not_before"] = (now - timedelta(days=3)).isoformat()
            lease["expires_at"] = (now - timedelta(minutes=2)).isoformat()
            update_signed_lease(database, private_key, lease)
            assert_parity(runtime, port, request, "expired signed lease")
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            runtime._server = None
            database.close()

    print("Authorization differential certification passed.")


if __name__ == "__main__":
    main()
