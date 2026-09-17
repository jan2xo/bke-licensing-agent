#!/usr/bin/env python3
"""Differential certification for Gen2 signed-lease activation."""

from __future__ import annotations

import base64
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from bke_licensing_agent.api.client import LicensingPlatformClient  # noqa: E402
from bke_licensing_agent.api.config import ApiConfig  # noqa: E402
from bke_licensing_agent.licensing.lease import LeaseVerifier  # noqa: E402
from bke_licensing_agent.licensing.service import LicensingService  # noqa: E402
from bke_licensing_agent.runtime import InstalledAgentRuntime  # noqa: E402
from bke_licensing_agent.storage.database import Database  # noqa: E402

PRODUCT_ID = "gen2-activation-demo"
VERSION = "1.0.0"
INSTALLATION_ID = "installation-gen2-activation-1234567890"
LICENSE_KEY = "GEN2-CERT-LICENSE"
KEY_ID = "gen2-activation-key"
LICENSE_ID = "license-gen2-activation"
LEASE_ID = "lease-gen2-activation"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@dataclass
class PlatformState:
    private_key: Ed25519PrivateKey
    public_key: str
    scenario: str = "success"
    key_calls: int = 0
    activation_calls: int = 0
    activation_requests: list[dict[str, object]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def reset(self, scenario: str) -> None:
        self.scenario = scenario
        self.key_calls = 0
        self.activation_calls = 0
        self.activation_requests.clear()
        self.errors.clear()


class PlatformHandler(BaseHTTPRequestHandler):
    state: PlatformState

    def _json(self, status: int, body: dict[str, object]) -> None:
        raw = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # noqa: N802
        if self.path != "/keys":
            self._json(404, {"error": "not_found"})
            return
        self.state.key_calls += 1
        if self.state.scenario == "no_keys":
            self._json(200, {"keys": []})
            return
        self._json(200, {"keys": [{
            "key_id": KEY_ID,
            "public_key": self.state.public_key,
            "algorithm": "Ed25519",
        }]})

    def do_POST(self):  # noqa: N802
        if self.path != "/api/licenses/activate":
            self._json(404, {"error": "not_found"})
            return
        self.state.activation_calls += 1
        if self.headers.get("x-bke-licensing-version") != "bke.licensing.v3":
            self.state.errors.append("missing or invalid x-bke-licensing-version")
        try:
            length = int(self.headers.get("content-length", "0"))
            body = json.loads(self.rfile.read(length))
        except Exception as exc:  # pragma: no cover - diagnostic path
            self.state.errors.append(f"invalid request JSON: {exc}")
            self._json(400, {"error": "invalid"})
            return
        if not isinstance(body, dict):
            self.state.errors.append("activation request was not an object")
            self._json(400, {"error": "invalid"})
            return
        self.state.activation_requests.append(dict(body))
        expected_fields = {
            "licenseKey", "installationId", "deviceId", "operationId",
            "productVersion", "operatingSystem", "architecture",
        }
        if set(body) != expected_fields:
            self.state.errors.append(f"activation request fields drifted: {sorted(body)}")
        if body.get("licenseKey") != LICENSE_KEY:
            self.state.errors.append("licenseKey drifted")
        if body.get("installationId") != INSTALLATION_ID:
            self.state.errors.append("installationId drifted")
        if body.get("productVersion") != VERSION:
            self.state.errors.append("productVersion drifted")
        try:
            uuid.UUID(str(body.get("operationId")))
        except ValueError:
            self.state.errors.append("operationId is not a UUID")

        if self.state.scenario == "remote_500":
            self._json(503, {"error": "temporary"})
            return

        now = datetime.now(timezone.utc)
        product_id = PRODUCT_ID
        installation_id = str(body.get("installationId"))
        device_id = str(body.get("deviceId"))
        version = VERSION
        if self.state.scenario == "wrong_product":
            product_id = "wrong-product"
        elif self.state.scenario == "wrong_installation":
            installation_id = "wrong-installation-123456789012345"
        elif self.state.scenario == "wrong_device":
            device_id = "f" * 64
        elif self.state.scenario == "wrong_version":
            version = "9.9.9"

        expires_at = now + timedelta(hours=1)
        if self.state.scenario == "expired":
            expires_at = now - timedelta(minutes=2)

        lease = {
            "license_id": LICENSE_ID,
            "lease_id": LEASE_ID,
            "generation": 1,
            "server_revision": 4,
            "product_id": product_id,
            "installation_id": installation_id,
            "device_id": device_id,
            "version": version,
            "issuer": "gen2-activation-certification",
            "issued_at": (now - timedelta(minutes=3)).isoformat(),
            "not_before": (now - timedelta(minutes=2)).isoformat(),
            "expires_at": expires_at.isoformat(),
            "key_id": KEY_ID,
            "algorithm": "Ed25519",
            "revoked": False,
            "superseded_by": None,
        }
        payload = json.dumps(lease, separators=(",", ":"))
        signature = self.state.private_key.sign(payload.encode())
        if self.state.scenario == "bad_signature":
            signature = b"x" * 64
        self._json(201, {"lease": {
            "payload": payload,
            "signature": base64.b64encode(signature).decode(),
            "key_id": KEY_ID,
            "algorithm": "Ed25519",
        }})

    def log_message(self, *_args):
        return


class Sessions:
    @staticmethod
    def current_session() -> object:
        return object()


class RequestIdentity:
    def __init__(self, installation_id: str):
        self.installation_id = installation_id

    def load_or_create(self) -> str:
        return self.installation_id


def write_manifest(data_dir: Path) -> None:
    database = Database(data_dir / "agent.db")
    product_root = data_dir / "product"
    product_root.mkdir(parents=True, exist_ok=True)
    entry_point = product_root / "app.bin"
    entry_point.write_bytes(b"gen2-activation")
    manifest_path = product_root / "bke.manifest.json"
    manifest = {
        "schemaVersion": 1,
        "productId": PRODUCT_ID,
        "displayName": "Gen2 Activation Demo",
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
    database.close()


def snapshot(data_dir: Path) -> dict[str, object]:
    connection = sqlite3.connect(data_dir / "agent.db")
    connection.row_factory = sqlite3.Row
    license_row = connection.execute(
        """SELECT license_id, product_id, product_version, installation_id, device_id, lease_id,
                  generation, server_revision, status, key_id, signed_algorithm
           FROM verified_licenses ORDER BY lease_id LIMIT 1"""
    ).fetchone()
    binding_row = connection.execute(
        """SELECT product_id, installation_id, device_id, active_license_id, active_lease_id,
                  generation, server_revision, binding_version
           FROM active_license_bindings ORDER BY product_id LIMIT 1"""
    ).fetchone()
    connection.close()
    key_dir = data_dir / "trusted-keys"
    return {
        "license": dict(license_row) if license_row else None,
        "binding": dict(binding_row) if binding_row else None,
        "trusted_keys": sorted(path.stem for path in key_dir.glob("*.pem")) if key_dir.exists() else [],
    }


def python_activate(data_dir: Path, platform_url: str, body: dict[str, str]) -> tuple[dict[str, object], dict[str, object]]:
    database = Database(data_dir / "agent.db")
    runtime = InstalledAgentRuntime(database=database)
    try:
        manifest = runtime._validated_product(body["product_id"], body["version"])
        if manifest is None:
            result = {"authorized": False, "reason": "invalid_product_context"}
            return result, snapshot(data_dir)
        try:
            client = LicensingPlatformClient(ApiConfig(
                base_url=platform_url,
                environment="test",
                allow_insecure_local=True,
            ))
            metadata = client.retrieve_key_metadata("")
            trusted = {item.key_id: item.public_key for item in metadata.keys if item.algorithm == "Ed25519"}
            if not trusted:
                return {"authorized": False, "reason": "trusted_keys_unavailable"}, snapshot(data_dir)
            trusted_dir = data_dir / "trusted-keys"
            trusted_dir.mkdir(parents=True, exist_ok=True)
            for key_id, public_key in trusted.items():
                (trusted_dir / f"{key_id}.pem").write_text(public_key)
            service = LicensingService(
                client=client,
                sessions=Sessions(),  # type: ignore[arg-type]
                identity=RequestIdentity(body["installation_id"]),  # type: ignore[arg-type]
                fingerprint=runtime.fingerprint,
            )
            decision = service.activate(manifest, body["license_key"], LeaseVerifier(trusted), runtime.repository)
            result = {"authorized": decision.authorized, "reason": decision.reason or decision.state.value}
        except Exception:
            result = {"authorized": False, "reason": "activation_failed"}
        return result, snapshot(data_dir)
    finally:
        runtime.close()


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


def dotnet_activate(data_dir: Path, platform_url: str, body: dict[str, str]) -> tuple[dict[str, object], dict[str, object]]:
    host_dll = ROOT / "dotnet" / "src" / "BKE.LicensingAgent.Host" / "bin" / "Release" / "net10.0" / "BKE.LicensingAgent.Host.dll"
    port = free_port()
    env = os.environ.copy()
    env.update({
        "BKE_AGENT_DATA_DIR": str(data_dir),
        "BKE_AGENT_PORT": str(port),
        "BKE_AGENT_VNEXT_ENABLE": "1",
        "BKE_AGENT_VNEXT_ALLOW_INSECURE_LOCAL": "1",
        "BKE_PLATFORM_BASE_URL": platform_url,
    })
    process = subprocess.Popen(
        ["dotnet", str(host_dll)], cwd=ROOT, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        wait_for_host(port, process)
        raw = json.dumps(body, separators=(",", ":")).encode()
        request = Request(
            f"http://127.0.0.1:{port}/v1/activate",
            data=raw,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=30) as response:
            assert response.status == 200, response.status
            result = json.loads(response.read())
        return result, snapshot(data_dir)
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def call_summary(state: PlatformState) -> dict[str, object]:
    requests: list[dict[str, object]] = []
    for item in state.activation_requests:
        clean = dict(item)
        operation_id = clean.pop("operationId", None)
        try:
            uuid.UUID(str(operation_id))
            operation_valid = True
        except ValueError:
            operation_valid = False
        clean["operationId_valid_uuid"] = operation_valid
        requests.append(clean)
    return {
        "key_calls": state.key_calls,
        "activation_calls": state.activation_calls,
        "requests": requests,
        "errors": list(state.errors),
    }


def run_case(root: Path, platform_url: str, state: PlatformState, scenario: str, request_product: str = PRODUCT_ID) -> None:
    body = {
        "product_id": request_product,
        "version": VERSION,
        "installation_id": INSTALLATION_ID,
        "license_key": LICENSE_KEY,
    }

    python_dir = root / f"python-{scenario}"
    python_dir.mkdir()
    write_manifest(python_dir)
    state.reset(scenario)
    python_result, python_state = python_activate(python_dir, platform_url, body)
    python_calls = call_summary(state)

    dotnet_dir = root / f"dotnet-{scenario}"
    dotnet_dir.mkdir()
    write_manifest(dotnet_dir)
    state.reset(scenario)
    dotnet_result, dotnet_state = dotnet_activate(dotnet_dir, platform_url, body)
    dotnet_calls = call_summary(state)

    if python_result != dotnet_result:
        raise AssertionError(f"{scenario} result drifted\nPython: {python_result}\n.NET: {dotnet_result}")
    if python_state != dotnet_state:
        raise AssertionError(f"{scenario} persisted state drifted\nPython: {python_state}\n.NET: {dotnet_state}")
    if python_calls != dotnet_calls:
        raise AssertionError(f"{scenario} platform contract drifted\nPython: {python_calls}\n.NET: {dotnet_calls}")
    if python_calls["errors"]:
        raise AssertionError(f"{scenario} invalid platform request: {python_calls['errors']}")
    print(f"PASS activation {scenario}: {python_result['reason']}")


def main() -> None:
    host_dll = ROOT / "dotnet" / "src" / "BKE.LicensingAgent.Host" / "bin" / "Release" / "net10.0" / "BKE.LicensingAgent.Host.dll"
    if not host_dll.exists():
        raise RuntimeError(f"Build Gen2 host first: {host_dll}")

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    state = PlatformState(private_key, public_key)
    PlatformHandler.state = state
    server = ThreadingHTTPServer(("127.0.0.1", 0), PlatformHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    platform_url = f"http://127.0.0.1:{server.server_port}"

    try:
        with tempfile.TemporaryDirectory(prefix="bke-gen2-activation-") as temp:
            root = Path(temp)
            run_case(root, platform_url, state, "invalid_product", request_product="missing-product")
            run_case(root, platform_url, state, "no_keys")
            run_case(root, platform_url, state, "success")
            run_case(root, platform_url, state, "bad_signature")
            run_case(root, platform_url, state, "wrong_product")
            run_case(root, platform_url, state, "wrong_installation")
            run_case(root, platform_url, state, "wrong_device")
            run_case(root, platform_url, state, "wrong_version")
            run_case(root, platform_url, state, "expired")
            run_case(root, platform_url, state, "remote_500")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    print("Activation differential certification passed.")


if __name__ == "__main__":
    main()
