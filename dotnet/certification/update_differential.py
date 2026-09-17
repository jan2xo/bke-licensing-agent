#!/usr/bin/env python3
"""Differential certification for Gen2 signed update discovery/check."""
from __future__ import annotations

import base64
import json
import os
import socket
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
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from bke_licensing_agent.api.client import LicensingPlatformClient  # noqa: E402
from bke_licensing_agent.api.config import ApiConfig  # noqa: E402
from bke_licensing_agent.local_api import LocalAuthorizationServer  # noqa: E402
from bke_licensing_agent.runtime import InstalledAgentRuntime  # noqa: E402
from bke_licensing_agent.storage.database import Database  # noqa: E402

PRODUCT_ID = "gen2-update-demo"
VERSION = "1.0.0"
LATEST_VERSION = "2.0.0"
LEASE_KEY_ID = "lease-envelope-key"
UPDATE_KEY_ID = "gen2-update-key"
CONTENT_TYPE = "application/vnd.bke.update-package+zip"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def canonical_policy(unsigned: dict[str, object]) -> bytes:
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


@dataclass
class PlatformState:
    private_key: Ed25519PrivateKey
    scenario: str = "up_to_date"
    calls: list[dict[str, object]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def reset(self, scenario: str) -> None:
        self.scenario = scenario
        self.calls.clear()
        self.errors.clear()

    def signed_policy(self, *, changed: bool = False) -> dict[str, object]:
        unsigned: dict[str, object] = {
            "schema": "bke.update-policy.v1",
            "product_id": "wrong-product" if self.scenario == "wrong_context" else PRODUCT_ID,
            "current_version": VERSION,
            "latest_version": LATEST_VERSION,
            "minimum_supported_version": VERSION,
            "channel": "stable",
            "platform": "linux",
            "architecture": "x64",
            "release_id": "release-gen2-2",
            "artifact_id": "artifact-gen2-2",
            "artifact_sha256": "a" * 64,
            "artifact_size": 123,
            "content_type": "application/octet-stream" if self.scenario == "wrong_content_type" else CONTENT_TYPE,
            "published_at": "2026-09-17T00:00:00Z",
            "issued_at": "2026-09-17T01:00:00Z" if changed else "2026-09-17T00:30:00Z",
            "revision": 2,
            "signing_key_id": UPDATE_KEY_ID,
            "algorithm": "Ed25519",
        }
        signature = self.private_key.sign(canonical_policy(unsigned))
        if self.scenario == "bad_signature":
            signature = b"x" * 64
        return {**unsigned, "signature": base64.b64encode(signature).decode()}


class PlatformHandler(BaseHTTPRequestHandler):
    state: PlatformState

    def _json(self, status: int, body: object) -> None:
        raw = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):  # noqa: N802
        if self.path != "/api/agent/updates/check":
            self._json(404, {"error": "not_found"})
            return
        try:
            length = int(self.headers.get("content-length", "0"))
            body = json.loads(self.rfile.read(length))
        except Exception as exc:  # pragma: no cover
            self.state.errors.append(f"invalid request JSON: {exc}")
            self._json(400, {"error": "INVALID_REQUEST"})
            return

        request_id = self.headers.get("x-request-id", "")
        try:
            uuid.UUID(request_id)
            request_id_valid = True
        except ValueError:
            request_id_valid = False
            self.state.errors.append("x-request-id is not a UUID")
        self.state.calls.append({
            "body": body,
            "protocol": self.headers.get("x-bke-licensing-version"),
            "user_agent": self.headers.get("user-agent"),
            "request_id": request_id,
            "request_id_valid": request_id_valid,
        })
        if self.headers.get("x-bke-licensing-version") != "bke.licensing.v3":
            self.state.errors.append("missing updater protocol header")
        if self.headers.get("user-agent") != "bke-licensing-agent":
            self.state.errors.append("updater user-agent drifted")

        scenario = self.state.scenario
        if scenario == "provider_503":
            self._json(503, {"error": "temporary"})
            return
        if scenario == "policy_denied_403":
            self._json(403, {"error": "POLICY_DENIED"})
            return
        if scenario == "mapped_verification_400":
            self._json(400, {"error": "RELEASE_NOT_VERIFIED"})
            return
        if scenario == "malformed_json":
            raw = b"{not-json"
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        if scenario == "malformed_schema":
            self._json(200, {"status": "unexpected"})
            return
        if scenario == "up_to_date":
            self._json(200, {"status": "up_to_date"})
            return

        changed = scenario == "same_revision_changed" and len(self.state.calls) >= 2
        self._json(200, {
            "status": "update_available",
            "policy": self.state.signed_policy(changed=changed),
            "download_url": "https://download.invalid/update.zip",
        })

    def log_message(self, *_args):
        return


def write_fixture(data_dir: Path, public_key_pem: str, *, with_lease: bool = True) -> None:
    os.environ["BKE_AGENT_DATA_DIR"] = str(data_dir)
    database = Database(data_dir / "agent.db")
    product_root = data_dir / "product"
    product_root.mkdir(parents=True, exist_ok=True)
    entry_point = product_root / "app.bin"
    entry_point.write_bytes(b"gen2-update")
    manifest_path = product_root / "bke.manifest.json"
    manifest = {
        "schemaVersion": 1,
        "productId": PRODUCT_ID,
        "displayName": "Gen2 Update Demo",
        "version": VERSION,
        "entryPoint": "app.bin",
        "updateChannel": "stable",
        "minimumAgentVersion": "1.0.0",
        "platform": "linux",
        "architecture": "x64",
    }
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    now = datetime.now(timezone.utc)
    with database.connection:
        database.connection.execute(
            """INSERT INTO discovered_products
               (product_id, display_name, version, manifest_path, product_root, entry_point_path, discovered_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (PRODUCT_ID, manifest["displayName"], VERSION, str(manifest_path), str(product_root),
             str(entry_point), now.isoformat()),
        )
        if with_lease:
            database.connection.execute(
                """INSERT INTO verified_licenses VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                ("license-update-1", PRODUCT_ID, VERSION, "installation-update-1", "device-update-1",
                 "lease-update-1", 1, 1, now.isoformat(), now.isoformat(),
                 (now + timedelta(days=1)).isoformat(), "verified", LEASE_KEY_ID,
                 now.isoformat(), now.isoformat(), "{\"lease\":\"opaque\"}",
                 "opaque-signature", "Ed25519"),
            )
    database.close()
    trusted = data_dir / "trusted-keys"
    trusted.mkdir(parents=True, exist_ok=True)
    (trusted / f"{UPDATE_KEY_ID}.pem").write_text(public_key_pem, encoding="utf-8")


def normalize_dynamic(value: object) -> object:
    if isinstance(value, dict):
        return {
            key: normalize_dynamic(item)
            for key, item in sorted(value.items())
            if key not in {"verified_at", "last_attempt_at"}
        }
    if isinstance(value, list):
        return [normalize_dynamic(item) for item in value]
    return value


def snapshot(data_dir: Path) -> dict[str, object]:
    root = data_dir / "updates"
    result: dict[str, object] = {}
    if not root.exists():
        return result
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(data_dir).as_posix()
        try:
            parsed = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            parsed = path.read_text(encoding="utf-8", errors="replace")
        result[relative] = normalize_dynamic(parsed)
    return result


def http_post(url: str, body: dict[str, object]) -> tuple[int, dict[str, object]]:
    raw = json.dumps(body, separators=(",", ":")).encode()
    request = Request(url, data=raw, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read())
    except HTTPError as exc:
        return exc.code, json.loads(exc.read())


def python_checks(data_dir: Path, platform_url: str, bodies: list[dict[str, object]]) -> tuple[list[tuple[int, dict[str, object]]], dict[str, object]]:
    os.environ["BKE_AGENT_DATA_DIR"] = str(data_dir)
    database = Database(data_dir / "agent.db")
    runtime = InstalledAgentRuntime(database=database, port=0)
    runtime.update_discovery.client = LicensingPlatformClient(ApiConfig(
        base_url=platform_url,
        environment="test",
        allow_insecure_local=True,
    ))
    try:
        results: list[tuple[int, dict[str, object]]] = []
        with LocalAuthorizationServer(
            lambda _request: {"authorized": False, "reason": "activation_required"},
            update_check=runtime.check_update_capability,
        ) as server:
            for body in bodies:
                results.append(http_post(f"{server.url}/v1/updates/check", body))
        return results, snapshot(data_dir)
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


def dotnet_checks(data_dir: Path, platform_url: str, bodies: list[dict[str, object]]) -> tuple[list[tuple[int, dict[str, object]]], dict[str, object]]:
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
        results = [http_post(f"http://127.0.0.1:{port}/v1/updates/check", body) for body in bodies]
        return results, snapshot(data_dir)
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def calls_summary(state: PlatformState) -> dict[str, object]:
    ids = [str(call["request_id"]) for call in state.calls]
    return {
        "count": len(state.calls),
        "bodies": [call["body"] for call in state.calls],
        "protocols": [call["protocol"] for call in state.calls],
        "user_agents": [call["user_agent"] for call in state.calls],
        "request_ids_valid": all(bool(call["request_id_valid"]) for call in state.calls),
        "one_request_id_when_retrying": len(set(ids)) <= 1,
        "errors": list(state.errors),
    }


def run_case(
    root: Path,
    platform_url: str,
    state: PlatformState,
    public_key_pem: str,
    scenario: str,
    *,
    request_product: str = PRODUCT_ID,
    with_lease: bool = True,
    requested_version: object = ...,
    calls: int = 1,
) -> None:
    body: dict[str, object] = {"product_id": request_product, "current_version": VERSION}
    if requested_version is not ...:
        body["requested_version"] = requested_version
    bodies = [dict(body) for _ in range(calls)]

    python_dir = root / f"python-{scenario}"
    python_dir.mkdir()
    write_fixture(python_dir, public_key_pem, with_lease=with_lease)
    state.reset(scenario)
    python_result, python_snapshot = python_checks(python_dir, platform_url, bodies)
    python_calls = calls_summary(state)

    dotnet_dir = root / f"dotnet-{scenario}"
    dotnet_dir.mkdir()
    write_fixture(dotnet_dir, public_key_pem, with_lease=with_lease)
    state.reset(scenario)
    dotnet_result, dotnet_snapshot = dotnet_checks(dotnet_dir, platform_url, bodies)
    dotnet_calls = calls_summary(state)

    if python_result != dotnet_result:
        raise AssertionError(f"{scenario} response drifted\nPython: {python_result}\n.NET: {dotnet_result}")
    if python_snapshot != dotnet_snapshot:
        raise AssertionError(
            f"{scenario} cached state drifted\nPython: {json.dumps(python_snapshot, sort_keys=True)}\n"
            f".NET:   {json.dumps(dotnet_snapshot, sort_keys=True)}"
        )
    if python_calls != dotnet_calls:
        raise AssertionError(f"{scenario} authority calls drifted\nPython: {python_calls}\n.NET: {dotnet_calls}")
    if python_calls["errors"]:
        raise AssertionError(f"{scenario} invalid authority contract: {python_calls['errors']}")
    print(f"PASS update {scenario}: {python_result[-1][0]} {python_result[-1][1].get('status')}")


def main() -> None:
    host_dll = ROOT / "dotnet" / "src" / "BKE.LicensingAgent.Host" / "bin" / "Release" / "net10.0" / "BKE.LicensingAgent.Host.dll"
    if not host_dll.exists():
        raise RuntimeError(f"Build Gen2 host first: {host_dll}")

    private_key = Ed25519PrivateKey.generate()
    public_key_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    state = PlatformState(private_key)
    PlatformHandler.state = state
    server = ThreadingHTTPServer(("127.0.0.1", 0), PlatformHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    platform_url = f"http://127.0.0.1:{server.server_port}"

    try:
        with tempfile.TemporaryDirectory(prefix="bke-gen2-update-") as temp:
            root = Path(temp)
            run_case(root, platform_url, state, public_key_pem, "requested_version", requested_version="2.0.0")
            run_case(root, platform_url, state, public_key_pem, "requested_version_blank", requested_version="")
            run_case(root, platform_url, state, public_key_pem, "invalid_product", request_product="missing-product")
            run_case(root, platform_url, state, public_key_pem, "missing_lease", with_lease=False)
            run_case(root, platform_url, state, public_key_pem, "up_to_date")
            run_case(root, platform_url, state, public_key_pem, "valid_update")
            run_case(root, platform_url, state, public_key_pem, "bad_signature")
            run_case(root, platform_url, state, public_key_pem, "wrong_context")
            run_case(root, platform_url, state, public_key_pem, "wrong_content_type")
            run_case(root, platform_url, state, public_key_pem, "same_revision_changed", calls=2)
            run_case(root, platform_url, state, public_key_pem, "policy_denied_403")
            run_case(root, platform_url, state, public_key_pem, "provider_503")
            run_case(root, platform_url, state, public_key_pem, "mapped_verification_400")
            run_case(root, platform_url, state, public_key_pem, "malformed_json")
            run_case(root, platform_url, state, public_key_pem, "malformed_schema")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    print("Update discovery differential certification passed.")


if __name__ == "__main__":
    main()
