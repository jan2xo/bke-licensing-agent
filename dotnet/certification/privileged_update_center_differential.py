#!/usr/bin/env python3
"""Differential certification for Gen2 privileged installed-product update-center handoff."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import zipfile
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
from bke_licensing_agent.runtime import InstalledAgentRuntime  # noqa: E402
from bke_licensing_agent.storage.database import Database  # noqa: E402
from bke_licensing_agent.updates import acquisition as acquisition_module  # noqa: E402
from bke_licensing_agent.updates import installed_privileged as installed_module  # noqa: E402
from bke_licensing_agent.updates import orchestrator as orchestrator_module  # noqa: E402

PRODUCT_ID = "gen2-privileged-demo"
VERSION = "1.0.0"
LATEST = "2.0.0"
UPDATE_KEY_ID = "gen2-update-key"
TARGET_KEY_ID = "bke-target-1"
AGENT_KEY_ID = "agent-local-1"
LEASE_KEY_ID = "lease-envelope-key"
CONTENT_TYPE = "application/vnd.bke.update-package+zip"
TARGET_ROOT = r"C:\Program Files\BKE Digital Solutions"
INSTALL_ROOT = TARGET_ROOT + r"\Gen2 Privileged Demo"
ENTRY_POINT = "Demo.exe"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def canonical(document: dict[str, object]) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def public_pem(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def private_pem(key: Ed25519PrivateKey) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


@dataclass
class AuthorityState:
    update_key: Ed25519PrivateKey
    artifact: bytes
    base_url: str = ""
    scenario: str = "same_revision"
    calls: list[dict[str, object]] = field(default_factory=list)
    downloads: int = 0
    errors: list[str] = field(default_factory=list)

    def reset(self, scenario: str) -> None:
        self.scenario = scenario
        self.calls.clear()
        self.downloads = 0
        self.errors.clear()

    def policy(self, revision: int) -> dict[str, object]:
        unsigned: dict[str, object] = {
            "schema": "bke.update-policy.v1",
            "product_id": PRODUCT_ID,
            "current_version": VERSION,
            "latest_version": LATEST,
            "minimum_supported_version": VERSION,
            "channel": "stable",
            "platform": "windows",
            "architecture": "x64",
            "release_id": f"release-gen2-{revision}",
            "artifact_id": f"artifact-gen2-{revision}",
            "artifact_sha256": hashlib.sha256(self.artifact).hexdigest(),
            "artifact_size": len(self.artifact),
            "content_type": CONTENT_TYPE,
            "published_at": "2026-09-17T00:00:00Z",
            "issued_at": f"2026-09-17T0{min(revision,9)}:00:00Z",
            "revision": revision,
            "signing_key_id": UPDATE_KEY_ID,
            "algorithm": "Ed25519",
        }
        return {**unsigned, "signature": base64.b64encode(self.update_key.sign(canonical(unsigned))).decode()}


class AuthorityHandler(BaseHTTPRequestHandler):
    state: AuthorityState

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
        length = int(self.headers.get("content-length", "0"))
        body = json.loads(self.rfile.read(length))
        self.state.calls.append({
            "body": body,
            "protocol": self.headers.get("x-bke-licensing-version"),
            "user_agent": self.headers.get("user-agent"),
        })
        if self.headers.get("x-bke-licensing-version") != "bke.licensing.v3":
            self.state.errors.append("missing updater protocol header")
        if self.state.scenario == "remote_up_to_date":
            self._json(200, {"status": "up_to_date"})
            return
        revision = 2 if self.state.scenario == "same_revision" else 3
        self._json(200, {
            "status": "update_available",
            "policy": self.state.policy(revision),
            "download_url": self.state.base_url + "/artifact",
        })

    def do_GET(self):  # noqa: N802
        if self.path != "/artifact":
            self._json(404, {"error": "not_found"})
            return
        self.state.downloads += 1
        payload = self.state.artifact + (b"tampered" if self.state.scenario == "bad_artifact" else b"")
        self.send_response(200)
        self.send_header("content-type", "application/octet-stream")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args):
        return


def make_artifact(path: Path) -> bytes:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(ENTRY_POINT, b"gen2-v2")
        archive.writestr("assets/config.json", b'{"version":"2.0.0"}')
    return path.read_bytes()


def signed_target(key: Ed25519PrivateKey, *, tampered: bool = False) -> dict[str, object]:
    unsigned: dict[str, object] = {
        "schema": "bke.install-target-policy.v1",
        "policy_id": "gen2-demo-windows",
        "revision": 1,
        "product_id": PRODUCT_ID,
        "platform": "windows",
        "architecture": "x64",
        "install_root": INSTALL_ROOT,
        "entry_point": ENTRY_POINT,
        "signing_key_id": TARGET_KEY_ID,
        "algorithm": "Ed25519",
    }
    signature = key.sign(canonical(unsigned))
    document = {**unsigned, "signature": base64.b64encode(signature).decode()}
    if tampered:
        document["install_root"] = r"C:\Windows\System32"
    return document


def write_fixture(data_dir: Path, update_key: Ed25519PrivateKey, target_key: Ed25519PrivateKey,
                  agent_key: Ed25519PrivateKey, artifact: bytes, *, state: str,
                  tampered_target: bool = False) -> None:
    os.environ["BKE_AGENT_DATA_DIR"] = str(data_dir)
    database = Database(data_dir / "agent.db")
    product_root = data_dir / "product"
    product_root.mkdir(parents=True, exist_ok=True)
    entry = product_root / ENTRY_POINT
    entry.write_bytes(b"gen2-v1")
    manifest_path = product_root / "bke.manifest.json"
    manifest = {
        "schemaVersion": 1,
        "productId": PRODUCT_ID,
        "displayName": "Gen2 Privileged Demo",
        "version": VERSION,
        "entryPoint": ENTRY_POINT,
        "updateChannel": "stable",
        "minimumAgentVersion": "1.0.0",
        "platform": "windows",
        "architecture": "x64",
    }
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    now = datetime.now(timezone.utc)
    with database.connection:
        database.connection.execute(
            """INSERT INTO discovered_products
               (product_id, display_name, version, manifest_path, product_root, entry_point_path, discovered_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (PRODUCT_ID, manifest["displayName"], VERSION, str(manifest_path), str(product_root), str(entry), now.isoformat()),
        )
        database.connection.execute(
            """INSERT INTO verified_licenses VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ("license-update-1", PRODUCT_ID, VERSION, "installation-update-1", "device-update-1",
             "lease-update-1", 1, 1, now.isoformat(), now.isoformat(),
             (now + timedelta(days=1)).isoformat(), "verified", LEASE_KEY_ID,
             now.isoformat(), now.isoformat(), "{\"lease\":\"opaque\"}", "opaque-signature", "Ed25519"),
        )
    database.close()

    trusted = data_dir / "trusted-keys"
    trusted.mkdir(parents=True, exist_ok=True)
    (trusted / f"{UPDATE_KEY_ID}.pem").write_text(public_pem(update_key), encoding="utf-8")

    runtime_root = data_dir / "privileged-runtime"
    helper = data_dir / "BKE Updater Helper.exe"
    helper.write_bytes(b"helper")
    agent_private = data_dir / "agent-private.pem"
    agent_private.write_text(private_pem(agent_key), encoding="utf-8")
    target_keys = data_dir / "target-keys"
    target_keys.mkdir()
    (target_keys / f"{TARGET_KEY_ID}.pem").write_text(public_pem(target_key), encoding="utf-8")
    target_policies = data_dir / "target-policies"
    target_policies.mkdir()
    (target_policies / "demo.json").write_text(
        json.dumps(signed_target(target_key, tampered=tampered_target), separators=(",", ":")), encoding="utf-8")
    (data_dir / "privileged-update.json").write_text(json.dumps({
        "runtime_root": str(runtime_root),
        "helper_executable": str(helper),
        "signing_key_id": AGENT_KEY_ID,
        "signing_private_key": str(agent_private),
        "target_keys_dir": str(target_keys),
        "target_policies_dir": str(target_policies),
        "approved_install_roots": [TARGET_ROOT],
        "expected_channel": "stable",
    }), encoding="utf-8")

    if state == "never_checked":
        return
    status_root = data_dir / "updates" / PRODUCT_ID / VERSION
    status_root.mkdir(parents=True, exist_ok=True)
    if state == "up_to_date":
        (status_root / "status.json").write_text(json.dumps({
            "state": "up_to_date", "product_id": PRODUCT_ID, "current_version": VERSION,
            "verified_at": now.isoformat().replace("+00:00", "Z"),
            "last_attempt_at": now.isoformat().replace("+00:00", "Z"),
        }), encoding="utf-8")
        return

    cached_policy = AuthorityState(update_key, artifact).policy(2)
    verified_at = now.isoformat().replace("+00:00", "Z")
    (status_root / "policy.json").write_text(json.dumps({"policy": cached_policy, "verified_at": verified_at}, separators=(",", ":")), encoding="utf-8")
    (status_root / "status.json").write_text(json.dumps({
        "state": "update_available", "product_id": PRODUCT_ID, "current_version": VERSION,
        "latest_version": LATEST, "release_id": "release-gen2-2", "revision": 2,
        "verified_at": verified_at, "last_attempt_at": verified_at,
    }, separators=(",", ":")), encoding="utf-8")
    revision_root = data_dir / "updates" / "core" / "policy-revisions"
    revision_root.mkdir(parents=True, exist_ok=True)
    (revision_root / f"{PRODUCT_ID}-windows-x64-stable.json").write_text('{"revision":2}', encoding="utf-8")


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


def post_json(url: str, body: dict[str, object]) -> dict[str, object]:
    raw = json.dumps(body, separators=(",", ":")).encode()
    request = Request(url, data=raw, headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(request, timeout=30) as response:
        assert response.status == 200, response.status
        return json.loads(response.read())


def python_open(data_dir: Path, platform_url: str, body: dict[str, object]) -> tuple[dict[str, object], list[str] | None]:
    os.environ["BKE_AGENT_DATA_DIR"] = str(data_dir)
    os.environ["BKE_PLATFORM_BASE_URL"] = "https://jl-bke.com"
    database = Database(data_dir / "agent.db")
    runtime = InstalledAgentRuntime(database=database, port=0)
    runtime.update_discovery.client = LicensingPlatformClient(ApiConfig(
        base_url=platform_url, environment="test", allow_insecure_local=True,
    ))
    captured: list[list[str]] = []
    original_acquire = installed_module.acquire_artifact
    original_invoke = orchestrator_module.invoke_privileged_self_update

    def acquire_local(url, destination, *, expected_size, expected_sha256):
        return acquisition_module.acquire_artifact(
            url, destination, expected_size=expected_size, expected_sha256=expected_sha256,
            allow_loopback_http=True,
        )

    installed_module.acquire_artifact = acquire_local
    orchestrator_module.invoke_privileged_self_update = lambda prepared, **_kwargs: captured.append(list(prepared.command))
    try:
        result = runtime.open_update_center(body)
        return result, captured[0] if captured else None
    finally:
        installed_module.acquire_artifact = original_acquire
        orchestrator_module.invoke_privileged_self_update = original_invoke
        runtime.close()


def dotnet_open(data_dir: Path, platform_url: str, body: dict[str, object]) -> tuple[dict[str, object], list[str] | None]:
    host_dll = ROOT / "dotnet" / "src" / "BKE.LicensingAgent.Host" / "bin" / "Release" / "net10.0" / "BKE.LicensingAgent.Host.dll"
    port = free_port()
    capture = data_dir / "captured-command.json"
    env = os.environ.copy()
    env.update({
        "BKE_AGENT_DATA_DIR": str(data_dir),
        "BKE_AGENT_PORT": str(port),
        "BKE_AGENT_VNEXT_ENABLE": "1",
        "BKE_AGENT_VNEXT_ALLOW_INSECURE_LOCAL": "1",
        "BKE_AGENT_VNEXT_PRIVILEGED_CAPTURE_PATH": str(capture),
        "BKE_PLATFORM_BASE_URL": platform_url,
    })
    env.pop("BKE_PRIVILEGED_CONFIG", None)
    process = subprocess.Popen(
        ["dotnet", str(host_dll)], cwd=ROOT, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        wait_for_host(port, process)
        result = post_json(f"http://127.0.0.1:{port}/v1/update-center/open", body)
        command = json.loads(capture.read_text()) if capture.exists() else None
        return result, command
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait(timeout=5)


def command_contract(command: list[str] | None) -> object:
    if command is None:
        return None
    forbidden = {"--install-root", "--executable", "--trusted-agent-key"}
    if forbidden.intersection(command):
        raise AssertionError(f"privileged command leaked caller authority: {command}")
    flags = [item for item in command if isinstance(item, str) and item.startswith("--")]
    tx = command[command.index("--transaction-id") + 1] if "--transaction-id" in command else None
    return {"flags": flags, "transaction_id": tx, "helper": Path(command[0]).name}


def verify_agent_request(data_dir: Path, agent_key: Ed25519PrivateKey) -> dict[str, object] | None:
    path = data_dir / "privileged-runtime" / "request.json"
    if not path.exists():
        return None
    document = json.loads(path.read_text())
    signature = base64.b64decode(document.pop("signature"), validate=True)
    agent_key.public_key().verify(signature, canonical(document))
    for field in ("request_id", "issued_at", "expires_at"):
        document[field] = "<dynamic>"
    return document


def privileged_snapshot(data_dir: Path, agent_key: Ed25519PrivateKey) -> dict[str, object]:
    runtime = data_dir / "privileged-runtime"
    result: dict[str, object] = {}
    for name in ("trust.json", "update-policy.json", "target-policy.json"):
        path = runtime / name
        result[name] = json.loads(path.read_text()) if path.exists() else None
    result["request.json"] = verify_agent_request(data_dir, agent_key)
    artifact = runtime / "artifact.bin"
    result["artifact_sha256"] = hashlib.sha256(artifact.read_bytes()).hexdigest() if artifact.exists() else None
    stage_root = runtime / "stage"
    result["stage"] = {
        path.relative_to(stage_root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(stage_root.rglob("*")) if path.is_file()
    } if stage_root.exists() else {}
    transactions = data_dir / "updates" / "core"
    states = []
    if transactions.exists():
        for path in sorted(transactions.glob("*/state.json")):
            value = json.loads(path.read_text())
            if "helper" in value:
                value["helper"] = Path(value["helper"]).name
            states.append(value)
    result["transactions"] = states
    return result


def normalized_calls(state: AuthorityState) -> dict[str, object]:
    return {"calls": state.calls, "downloads": state.downloads, "errors": state.errors}


def run_case(root: Path, platform_url: str, state: AuthorityState,
             update_key: Ed25519PrivateKey, target_key: Ed25519PrivateKey,
             agent_key: Ed25519PrivateKey, scenario: str, fixture_state: str,
             *, tampered_target: bool = False) -> None:
    body = {"product_id": PRODUCT_ID, "version": VERSION, "correlation_id": "corr-gen2-update"}

    python_dir = root / f"python-{scenario}"
    python_dir.mkdir()
    write_fixture(python_dir, update_key, target_key, agent_key, state.artifact,
                  state=fixture_state, tampered_target=tampered_target)
    state.reset(scenario)
    python_result, python_command = python_open(python_dir, platform_url, body)
    python_calls = normalized_calls(state)
    python_snapshot = privileged_snapshot(python_dir, agent_key)

    dotnet_dir = root / f"dotnet-{scenario}"
    dotnet_dir.mkdir()
    write_fixture(dotnet_dir, update_key, target_key, agent_key, state.artifact,
                  state=fixture_state, tampered_target=tampered_target)
    state.reset(scenario)
    dotnet_result, dotnet_command = dotnet_open(dotnet_dir, platform_url, body)
    dotnet_calls = normalized_calls(state)
    dotnet_snapshot = privileged_snapshot(dotnet_dir, agent_key)

    if python_result != dotnet_result:
        raise AssertionError(f"{scenario} outcome drifted\nPython: {python_result}\n.NET: {dotnet_result}")
    if python_calls != dotnet_calls:
        raise AssertionError(f"{scenario} authority contract drifted\nPython: {python_calls}\n.NET: {dotnet_calls}")
    if command_contract(python_command) != command_contract(dotnet_command):
        raise AssertionError(f"{scenario} command contract drifted\nPython: {python_command}\n.NET: {dotnet_command}")
    if python_snapshot != dotnet_snapshot:
        raise AssertionError(
            f"{scenario} privileged state drifted\nPython: {json.dumps(python_snapshot, sort_keys=True, indent=2)}\n"
            f".NET: {json.dumps(dotnet_snapshot, sort_keys=True, indent=2)}")
    if state.errors:
        raise AssertionError(f"{scenario} invalid authority request: {state.errors}")
    print(f"PASS privileged update-center {scenario}: {python_result['outcome']}/{python_result['reason']}")


def main() -> None:
    host_dll = ROOT / "dotnet" / "src" / "BKE.LicensingAgent.Host" / "bin" / "Release" / "net10.0" / "BKE.LicensingAgent.Host.dll"
    if not host_dll.exists():
        raise RuntimeError(f"Build Gen2 host first: {host_dll}")

    update_key = Ed25519PrivateKey.generate()
    target_key = Ed25519PrivateKey.generate()
    agent_key = Ed25519PrivateKey.generate()
    with tempfile.TemporaryDirectory(prefix="bke-gen2-privileged-artifact-") as artifact_temp:
        artifact = make_artifact(Path(artifact_temp) / "update.zip")
        state = AuthorityState(update_key, artifact)
        AuthorityHandler.state = state
        server = ThreadingHTTPServer(("127.0.0.1", 0), AuthorityHandler)
        state.base_url = f"http://127.0.0.1:{server.server_port}"
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory(prefix="bke-gen2-privileged-") as temp:
                root = Path(temp)
                run_case(root, state.base_url, state, update_key, target_key, agent_key,
                         "never_checked", "never_checked")
                run_case(root, state.base_url, state, update_key, target_key, agent_key,
                         "up_to_date", "up_to_date")
                run_case(root, state.base_url, state, update_key, target_key, agent_key,
                         "same_revision", "update_available")
                run_case(root, state.base_url, state, update_key, target_key, agent_key,
                         "remote_up_to_date", "update_available")
                run_case(root, state.base_url, state, update_key, target_key, agent_key,
                         "bad_target", "update_available", tampered_target=True)
                run_case(root, state.base_url, state, update_key, target_key, agent_key,
                         "bad_artifact", "update_available")
                run_case(root, state.base_url, state, update_key, target_key, agent_key,
                         "higher_revision", "update_available")
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)

    print("Privileged update-center differential certification passed.")


if __name__ == "__main__":
    main()
