#!/usr/bin/env python3
"""Differential certification for the Gen2 notification capability."""

from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from bke_licensing_agent.broadcasts import ProductBroadcastSynchronizer  # noqa: E402
from bke_licensing_agent.devices.fingerprint import DeviceFingerprint  # noqa: E402
from bke_licensing_agent.notification_local_api import NotificationLocalAuthorizationServer  # noqa: E402
from bke_licensing_agent.notification_runtime import NotificationEnabledAgentRuntime  # noqa: E402
from bke_licensing_agent.notifications import AgentNotificationService  # noqa: E402
from bke_licensing_agent.storage.database import Database  # noqa: E402

PRODUCT_ID = "gen2-notification-demo"
VERSION = "1.0.0"
INSTALLATION_ID = "installation-gen2-notifications-1"
KEY_ID = "gen2-notification-key"
LICENSE_ID = "license-gen2-notification-1"
LEASE_ID = "lease-gen2-notification-1"
BROADCAST_1 = "11111111-1111-4111-8111-111111111111"
BROADCAST_2 = "22222222-2222-4222-8222-222222222222"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


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


def write_manifest(root: Path, database: Database) -> None:
    product_root = root / "product"
    product_root.mkdir(parents=True)
    entry_point = product_root / "app.bin"
    entry_point.write_bytes(b"gen2-notifications")
    manifest_path = product_root / "bke.manifest.json"
    manifest = {
        "schemaVersion": 1,
        "productId": PRODUCT_ID,
        "displayName": "Gen2 Notification Demo",
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


def payload(*, broadcast_id: str = BROADCAST_1, code: str = "FREE_SUPPORT_ENDED",
            delivery_mode: str = "ONCE", ends_at: str | None = None) -> dict[str, object]:
    return {
        "capabilityId": "bke.product-broadcasts",
        "contractVersion": 1,
        "source": "bke-digital-solutions",
        "productId": PRODUCT_ID,
        "version": VERSION,
        "broadcasts": [{
            "broadcastId": broadcast_id,
            "code": code,
            "audience": "ALL_ACTIVE_CLIENTS",
            "priority": "HIGH",
            "deliveryMode": delivery_mode,
            "minimumVersion": None,
            "maximumVersion": None,
            "publishedAt": "2026-09-17T00:00:00.000Z",
            "startsAt": "2026-09-17T00:00:00.000Z",
            "endsAt": ends_at,
        }],
    }


def empty_payload() -> dict[str, object]:
    value = payload()
    value["broadcasts"] = []
    return value


class BroadcastState:
    def __init__(self) -> None:
        self.payload = empty_payload()
        self.dotnet_calls: list[dict[str, object]] = []
        self.python_calls: list[tuple[str, dict[str, object]]] = []


class OracleResponse:
    status_code = 200

    def __init__(self, state: BroadcastState):
        self._state = state

    def json(self):
        return json.loads(json.dumps(self._state.payload))


class OracleSession:
    def __init__(self, state: BroadcastState):
        self._state = state

    def get(self, url: str, **kwargs):
        self._state.python_calls.append((url, kwargs))
        return OracleResponse(self._state)


class BroadcastServer:
    def __init__(self, state: BroadcastState):
        self.state = state
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                parsed = urlparse(self.path)
                owner.state.dotnet_calls.append({
                    "path": parsed.path,
                    "query": parse_qs(parsed.query),
                    "accept": self.headers.get("Accept"),
                    "user_agent": self.headers.get("User-Agent"),
                })
                encoded = json.dumps(owner.state.payload, separators=(",", ":")).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, *_args):
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def request_json(base_url: str, path: str, body: dict[str, object]) -> tuple[int, dict[str, object]]:
    request = Request(
        f"{base_url}{path}",
        data=json.dumps(body, separators=(",", ":")).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except HTTPError as exc:
        return exc.code, json.loads(exc.read())


def normalized(value: object) -> object:
    if isinstance(value, dict):
        return {key: normalized(item) for key, item in value.items() if key not in {"created_at", "dismissed_at"}}
    if isinstance(value, list):
        return [normalized(item) for item in value]
    return value


def assert_http_parity(py_url: str, net_url: str, path: str, body: dict[str, object], label: str):
    py_status, py_body = request_json(py_url, path, body)
    net_status, net_body = request_json(net_url, path, body)
    left = (py_status, normalized(py_body))
    right = (net_status, normalized(net_body))
    if left != right:
        raise AssertionError(
            f"{label} drifted\nPython: {json.dumps(left, sort_keys=True)}\n"
            f".NET:   {json.dumps(right, sort_keys=True)}"
        )
    print(f"PASS {label}")
    return py_body, net_body


def notification_snapshot(database: Database) -> list[dict[str, object]]:
    rows = database.connection.execute(
        "SELECT id, product_id, code, severity, state, expires_at, dismissed_at "
        "FROM notifications ORDER BY product_id, code"
    ).fetchall()
    return [{
        "id": row["id"],
        "product_id": row["product_id"],
        "code": row["code"],
        "severity": row["severity"],
        "state": row["state"],
        "expires_at": row["expires_at"],
        "dismissed": row["dismissed_at"] is not None,
    } for row in rows]


def assert_db_parity(py_db: Database, net_db: Database, label: str) -> None:
    left = notification_snapshot(py_db)
    right = notification_snapshot(net_db)
    if left != right:
        raise AssertionError(
            f"{label} notification DB drifted\nPython: {json.dumps(left, sort_keys=True)}\n"
            f".NET:   {json.dumps(right, sort_keys=True)}"
        )
    print(f"PASS {label} DB side effects")


def install_authorized_fixture(root: Path, database: Database) -> None:
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
        "server_revision": 1,
        "product_id": PRODUCT_ID,
        "installation_id": INSTALLATION_ID,
        "device_id": device_id,
        "version": VERSION,
        "issuer": "gen2-notification-certification",
        "issued_at": now.isoformat(),
        "not_before": (now - timedelta(minutes=5)).isoformat(),
        "expires_at": (now + timedelta(days=1)).isoformat(),
        "key_id": KEY_ID,
        "algorithm": "Ed25519",
        "revoked": False,
        "superseded_by": None,
    }
    signed_payload = json.dumps(lease, separators=(",", ":"))
    signature = base64.b64encode(private_key.sign(signed_payload.encode())).decode()
    with database.connection:
        database.connection.execute(
            """INSERT INTO verified_licenses VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (LICENSE_ID, PRODUCT_ID, VERSION, INSTALLATION_ID, device_id, LEASE_ID, 1, 1,
             lease["issued_at"], lease["not_before"], lease["expires_at"], "verified", KEY_ID,
             now.isoformat(), now.isoformat(), signed_payload, signature, "Ed25519"),
        )
        database.connection.execute(
            """INSERT INTO active_license_bindings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (PRODUCT_ID, INSTALLATION_ID, device_id, LICENSE_ID, LEASE_ID, 1, 1, 1, now.isoformat()),
        )
    trusted = root / "trusted-keys"
    trusted.mkdir(exist_ok=True)
    (trusted / f"{KEY_ID}.pem").write_text(public_key, encoding="utf-8")


def main() -> None:
    host_dll = ROOT / "dotnet" / "src" / "BKE.LicensingAgent.Host" / "bin" / "Release" / "net10.0" / "BKE.LicensingAgent.Host.dll"
    if not host_dll.exists():
        raise RuntimeError(f"Build Gen2 host first: {host_dll}")

    with tempfile.TemporaryDirectory(prefix="bke-gen2-notifications-") as temp:
        root = Path(temp)
        py_root = root / "python"
        net_root = root / "dotnet"
        py_root.mkdir()
        net_root.mkdir()
        py_db = Database(py_root / "agent.db")
        net_db = Database(net_root / "agent.db")
        write_manifest(py_root, py_db)
        write_manifest(net_root, net_db)

        state = BroadcastState()
        py_runtime = object.__new__(NotificationEnabledAgentRuntime)
        py_runtime.database = py_db
        py_runtime.notifications = AgentNotificationService(py_db)
        py_runtime.product_broadcasts = ProductBroadcastSynchronizer(
            py_runtime.notifications,
            platform_base_url="https://oracle.invalid",
            session=OracleSession(state),
        )
        py_runtime._validated_product = lambda product_id, version: (
            object() if (product_id, version) == (PRODUCT_ID, VERSION) else None
        )
        auth_state = {"authorized": False, "reason": "activation_required"}
        py_runtime.authorize = lambda _request: dict(auth_state)

        with BroadcastServer(state) as broadcasts, NotificationLocalAuthorizationServer(
            lambda _request: dict(auth_state),
            notification_request=py_runtime.request_notification,
            notification_feed=py_runtime.notification_feed,
            notification_mark_read=py_runtime.notification_mark_read,
            notification_dismiss=py_runtime.notification_dismiss,
            notification_unread_count=py_runtime.notification_unread_count,
        ) as py_server:
            port = free_port()
            env = os.environ.copy()
            env["BKE_AGENT_VNEXT_ENABLE"] = "1"
            env["BKE_AGENT_DATA_DIR"] = str(net_root)
            env["BKE_AGENT_PORT"] = str(port)
            env["BKE_PLATFORM_BASE_URL"] = broadcasts.url
            env["BKE_AGENT_VNEXT_ALLOW_INSECURE_LOCAL"] = "1"
            process = subprocess.Popen(
                ["dotnet", str(host_dll)], cwd=ROOT, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            net_url = f"http://127.0.0.1:{port}"
            context = {
                "product_id": PRODUCT_ID,
                "version": VERSION,
                "installation_id": INSTALLATION_ID,
            }
            try:
                wait_for_host(port, process)

                py_body, net_body = assert_http_parity(
                    py_server.url, net_url, "/v1/notifications/request",
                    {**context, "code": "LICENSE_REQUIRED"},
                    "authoritative typed LICENSE_REQUIRED",
                )
                assert py_body["notification_id"] == net_body["notification_id"]
                license_notice_id = str(py_body["notification_id"])
                assert_db_parity(py_db, net_db, "typed notification")

                assert_http_parity(
                    py_server.url, net_url, "/v1/notifications/request",
                    {**context, "code": "TRIAL_ENDED"},
                    "typed remote-only code rejection",
                )
                assert_http_parity(
                    py_server.url, net_url, "/v1/notifications/request",
                    {**context, "code": "LICENSE_REQUIRED", "title": "REMOTE TEXT MUST NOT PASS"},
                    "arbitrary typed content rejection",
                )
                assert_http_parity(
                    py_server.url, net_url, "/v1/notifications/request",
                    {"product_id": "missing", "version": VERSION, "installation_id": INSTALLATION_ID, "code": "LICENSE_REQUIRED"},
                    "invalid typed product context",
                )

                assert_http_parity(
                    py_server.url, net_url, "/v1/notifications/feed",
                    {**context, "limit": 50, "include_dismissed": False},
                    "initial inbox feed",
                )
                assert_http_parity(
                    py_server.url, net_url, "/v1/notifications/unread-count",
                    context,
                    "initial unread count",
                )
                assert_http_parity(
                    py_server.url, net_url, "/v1/notifications/mark-read",
                    {**context, "notification_id": license_notice_id},
                    "mark LICENSE_REQUIRED read",
                )
                assert_db_parity(py_db, net_db, "mark read")
                assert_http_parity(
                    py_server.url, net_url, "/v1/notifications/feed",
                    {**context, "limit": 50, "include_dismissed": False},
                    "read-state feed",
                )

                state.payload = payload()
                feed_py, _ = assert_http_parity(
                    py_server.url, net_url, "/v1/notifications/feed",
                    {**context, "limit": 50, "include_dismissed": False},
                    "remote campaign materialization",
                )
                broadcast_id = next(item["id"] for item in feed_py["items"] if item["category"] == "Product")
                assert_db_parity(py_db, net_db, "remote campaign materialization")

                assert_http_parity(
                    py_server.url, net_url, "/v1/notifications/dismiss",
                    {**context, "notification_id": broadcast_id},
                    "dismiss remote campaign",
                )
                assert_db_parity(py_db, net_db, "dismiss remote campaign")
                assert_http_parity(
                    py_server.url, net_url, "/v1/notifications/feed",
                    {**context, "limit": 50, "include_dismissed": True},
                    "same campaign preserves dismissed state",
                )
                assert_db_parity(py_db, net_db, "same campaign state preservation")

                state.payload = payload(broadcast_id=BROADCAST_2)
                republished_py, _ = assert_http_parity(
                    py_server.url, net_url, "/v1/notifications/feed",
                    {**context, "limit": 50, "include_dismissed": False},
                    "republished campaign rearms unread",
                )
                broadcast_id = next(item["id"] for item in republished_py["items"] if item["category"] == "Product")
                assert_db_parity(py_db, net_db, "republished campaign")

                assert_http_parity(
                    py_server.url, net_url, "/v1/notifications/mark-read",
                    {**context, "notification_id": broadcast_id},
                    "mark remote campaign read",
                )
                state.payload = payload(broadcast_id=BROADCAST_2, delivery_mode="EVERY_LAUNCH")
                assert_http_parity(
                    py_server.url, net_url, "/v1/notifications/feed",
                    {**context, "limit": 50, "include_dismissed": False},
                    "EVERY_LAUNCH projects persisted read as unread",
                )
                assert_http_parity(
                    py_server.url, net_url, "/v1/notifications/unread-count",
                    context,
                    "EVERY_LAUNCH unread count",
                )
                assert_db_parity(py_db, net_db, "EVERY_LAUNCH does not rewrite persisted state")

                state.payload = empty_payload()
                assert_http_parity(
                    py_server.url, net_url, "/v1/notifications/feed",
                    {**context, "limit": 50, "include_dismissed": False},
                    "withdrawn campaign deactivation",
                )
                assert_db_parity(py_db, net_db, "withdrawn campaign")

                before = notification_snapshot(py_db)
                state.payload = payload(code="REMOTE_TEXT_MESSAGE")
                assert_http_parity(
                    py_server.url, net_url, "/v1/notifications/feed",
                    {**context, "limit": 50, "include_dismissed": True},
                    "untrusted remote code fails closed without transport failure",
                )
                assert notification_snapshot(py_db) == before
                assert_db_parity(py_db, net_db, "untrusted remote code")

                state.payload = empty_payload()
                install_authorized_fixture(net_root, net_db)
                auth_state.update({"authorized": True, "reason": "ALLOW"})
                assert_http_parity(
                    py_server.url, net_url, "/v1/notifications/feed",
                    {**context, "limit": 50, "include_dismissed": True},
                    "LICENSE_REQUIRED suppressed after authorization",
                )
                assert_http_parity(
                    py_server.url, net_url, "/v1/notifications/unread-count",
                    context,
                    "authorized unread count suppression",
                )
                assert_http_parity(
                    py_server.url, net_url, "/v1/notifications/request",
                    {**context, "code": "LICENSE_REQUIRED"},
                    "authorized typed notification rejection",
                )

                if not state.python_calls or not state.dotnet_calls:
                    raise AssertionError("Broadcast sync transport was not exercised")
                py_url, py_kwargs = state.python_calls[-1]
                dot_call = state.dotnet_calls[-1]
                assert py_url == "https://oracle.invalid/api/licensing-agent/notifications"
                assert py_kwargs["params"] == {"product_id": PRODUCT_ID, "version": VERSION}
                assert py_kwargs["allow_redirects"] is False
                assert dot_call["path"] == "/api/licensing-agent/notifications"
                assert dot_call["query"] == {"product_id": [PRODUCT_ID], "version": [VERSION]}
                assert dot_call["accept"] == "application/json"
                assert dot_call["user_agent"] == "BKE-Licensing-Agent/1"
                print("PASS product-broadcast transport contract")
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

        py_db.close()
        net_db.close()

    print("Notification differential certification passed.")


if __name__ == "__main__":
    main()
