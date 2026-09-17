#!/usr/bin/env python3
"""Differential certification for the Gen2 License Center capability."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

import bke_licensing_agent.runtime as runtime_module  # noqa: E402
from bke_licensing_agent.license_center.native_launcher import NativeLicenseCenterLauncher  # noqa: E402
from bke_licensing_agent.local_api import LocalAuthorizationServer  # noqa: E402
from bke_licensing_agent.runtime import InstalledAgentRuntime  # noqa: E402
from bke_licensing_agent.storage.database import Database  # noqa: E402

PRODUCT_ID = "gen2-license-center-demo"
VERSION = "1.0.0"
INSTALLATION_ID = "installation-license-center-12345678901234567890"


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
    entry_point.write_bytes(b"gen2-license-center")
    manifest_path = product_root / "bke.manifest.json"
    manifest = {
        "schemaVersion": 1,
        "productId": PRODUCT_ID,
        "displayName": "Gen2 License Center Demo",
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
            (
                PRODUCT_ID,
                manifest["displayName"],
                VERSION,
                str(manifest_path),
                str(product_root),
                str(entry_point),
                datetime.now(timezone.utc).isoformat(),
            ),
        )


def post_json(base_url: str, path: str, body: dict[str, str]) -> tuple[int, dict[str, object]]:
    request = Request(
        f"{base_url}{path}",
        data=json.dumps(body, separators=(",", ":")).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except HTTPError as error:
        return error.code, json.loads(error.read())


def get_page(base_url: str, product_id: str, version: str, installation_id: str) -> tuple[int, str]:
    query = urlencode({
        "product_id": product_id,
        "version": version,
        "installation_id": installation_id,
    })
    try:
        with urlopen(f"{base_url}/license-center?{query}", timeout=5) as response:
            return response.status, response.read().decode()
    except HTTPError as error:
        return error.code, error.read().decode(errors="replace")


def notification_state(database: Database) -> dict[str, object] | None:
    row = database.connection.execute(
        """SELECT id, product_id, code, severity, state, expires_at, dismissed_at
           FROM notifications WHERE product_id=? AND code='LICENSE_REQUIRED'""",
        (PRODUCT_ID,),
    ).fetchone()
    if row is None:
        return None
    return {
        "id": row["id"],
        "product_id": row["product_id"],
        "code": row["code"],
        "severity": row["severity"],
        "state": row["state"],
        "expires_at": row["expires_at"],
        "dismissed_at": row["dismissed_at"],
    }


def assert_notification_parity(python_db: Database, dotnet_db: Database, label: str) -> None:
    python_state = notification_state(python_db)
    dotnet_state = notification_state(dotnet_db)
    if python_state != dotnet_state:
        raise AssertionError(
            f"{label} notification drifted\nPython: {json.dumps(python_state, sort_keys=True)}\n"
            f".NET:   {json.dumps(dotnet_state, sort_keys=True)}"
        )


def write_fake_launcher(path: Path) -> None:
    path.write_text(
        """#!/usr/bin/env bash
set -eu
corr=''
notification=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --correlation-id) corr="$2"; shift 2 ;;
    --notification-code) notification="$2"; shift 2 ;;
    *) shift ;;
  esac
done
if [ "$notification" != "LICENSE_REQUIRED" ]; then
  exit 77
fi
case "$corr" in
  corr-success|corr-dismissed) exit 0 ;;
  corr-cancel) exit 2 ;;
  corr-activation-failed) exit 3 ;;
  corr-failed) exit 9 ;;
  *) exit 9 ;;
esac
""",
        encoding="utf-8",
    )
    path.chmod(0o755)


def assert_open_parity(
    python_url: str,
    dotnet_url: str,
    body: dict[str, str],
    label: str,
    *,
    expected_status: int = 200,
) -> dict[str, object]:
    python_status, python_result = post_json(python_url, "/v1/license-center/open", body)
    dotnet_status, dotnet_result = post_json(dotnet_url, "/v1/license-center/open", body)
    if python_status != dotnet_status or python_result != dotnet_result:
        raise AssertionError(
            f"{label} drifted\nPython ({python_status}): {json.dumps(python_result, sort_keys=True)}\n"
            f".NET ({dotnet_status}):   {json.dumps(dotnet_result, sort_keys=True)}"
        )
    if python_status != expected_status:
        raise AssertionError(f"{label}: expected HTTP {expected_status}, got {python_status}")
    print(f"PASS {label}: {python_result.get('outcome', python_result.get('reason'))}")
    return python_result


def main() -> None:
    if os.name == "nt":
        raise RuntimeError("License Center differential currently requires the POSIX Gen2 certification runner")

    host_dll = ROOT / "dotnet" / "src" / "BKE.LicensingAgent.Host" / "bin" / "Release" / "net10.0" / "BKE.LicensingAgent.Host.dll"
    if not host_dll.exists():
        raise RuntimeError(f"Build Gen2 host first: {host_dll}")
    fake_launcher = host_dll.parent / "bke-license-center"
    if fake_launcher.exists():
        fake_launcher.unlink()

    with tempfile.TemporaryDirectory(prefix="bke-gen2-license-center-") as temp:
        root = Path(temp)
        python_root = root / "python"
        dotnet_root = root / "dotnet"
        python_root.mkdir()
        dotnet_root.mkdir()

        python_db = Database(python_root / "agent.db")
        dotnet_db = Database(dotnet_root / "agent.db")
        write_manifest(python_root, python_db)
        write_manifest(dotnet_root, dotnet_db)

        python_port = free_port()
        dotnet_port = free_port()
        runtime = InstalledAgentRuntime(database=python_db, port=python_port)

        original_launcher = runtime_module.NativeLicenseCenterLauncher
        runtime_module.NativeLicenseCenterLauncher = lambda: NativeLicenseCenterLauncher(fake_launcher)

        env = os.environ.copy()
        env["BKE_AGENT_VNEXT_ENABLE"] = "1"
        env["BKE_AGENT_DATA_DIR"] = str(dotnet_root)
        env["BKE_AGENT_PORT"] = str(dotnet_port)
        process = subprocess.Popen(
            ["dotnet", str(host_dll)],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        try:
            wait_for_host(dotnet_port, process)
            dotnet_url = f"http://127.0.0.1:{dotnet_port}"

            with LocalAuthorizationServer(
                runtime.authorize,
                runtime.activate,
                runtime.open_license_center,
                port=python_port,
            ) as python_server:
                runtime._server = python_server  # type: ignore[assignment]
                python_url = python_server.url

                py_status, py_page = get_page(python_url, PRODUCT_ID, VERSION, INSTALLATION_ID)
                dn_status, dn_page = get_page(dotnet_url, PRODUCT_ID, VERSION, INSTALLATION_ID)
                if py_status != 200 or dn_status != 200:
                    raise AssertionError(f"browser page status drifted: Python={py_status} .NET={dn_status}")
                for page, label in ((py_page, "Python"), (dn_page, ".NET")):
                    if "BKE License Center" not in page or PRODUCT_ID not in page or "license_key" not in page:
                        raise AssertionError(f"{label} browser page lost activation contract")
                print("PASS browser activation page")

                missing_py_status, _ = get_page(python_url, PRODUCT_ID, VERSION, "")
                missing_dn_status, _ = get_page(dotnet_url, PRODUCT_ID, VERSION, "")
                if missing_py_status != 400 or missing_dn_status != 400:
                    raise AssertionError(
                        f"browser missing-context status drifted: Python={missing_py_status} .NET={missing_dn_status}"
                    )
                print("PASS browser page rejects missing product context")

                invalid = {
                    "product_id": "missing-product",
                    "version": VERSION,
                    "installation_id": INSTALLATION_ID,
                    "correlation_id": "corr-invalid-product",
                }
                assert_open_parity(python_url, dotnet_url, invalid, "invalid product context")
                assert_notification_parity(python_db, dotnet_db, "invalid product context")

                malformed = {
                    "product_id": PRODUCT_ID,
                    "version": VERSION,
                    "installation_id": INSTALLATION_ID,
                    "correlation_id": "corr-bad\nvalue",
                }
                assert_open_parity(
                    python_url,
                    dotnet_url,
                    malformed,
                    "invalid correlation id",
                    expected_status=400,
                )

                missing_binary = {
                    "product_id": PRODUCT_ID,
                    "version": VERSION,
                    "installation_id": INSTALLATION_ID,
                    "correlation_id": "corr-missing",
                }
                assert_open_parity(python_url, dotnet_url, missing_binary, "missing native License Center")
                assert_notification_parity(python_db, dotnet_db, "missing native License Center")

                write_fake_launcher(fake_launcher)
                for correlation, label, outcome, changed in (
                    ("corr-success", "authorization refresh", "authorization_refreshed", True),
                    ("corr-cancel", "customer cancellation", "cancelled", False),
                    ("corr-activation-failed", "activation failure", "activation_failed", False),
                    ("corr-failed", "unexpected native exit", "failed", False),
                ):
                    body = {
                        "product_id": PRODUCT_ID,
                        "version": VERSION,
                        "installation_id": INSTALLATION_ID,
                        "correlation_id": correlation,
                    }
                    result = assert_open_parity(python_url, dotnet_url, body, label)
                    if result["outcome"] != outcome or result["authorization_changed"] is not changed:
                        raise AssertionError(f"{label} mapped to the wrong terminal outcome: {result}")
                    assert_notification_parity(python_db, dotnet_db, label)

                dismissed_at = "2026-09-17T00:00:00+00:00"
                for database in (python_db, dotnet_db):
                    with database.connection:
                        database.connection.execute(
                            """UPDATE notifications SET state='dismissed', dismissed_at=?
                               WHERE product_id=? AND code='LICENSE_REQUIRED'""",
                            (dismissed_at, PRODUCT_ID),
                        )
                result = assert_open_parity(
                    python_url,
                    dotnet_url,
                    {
                        "product_id": PRODUCT_ID,
                        "version": VERSION,
                        "installation_id": INSTALLATION_ID,
                        "correlation_id": "corr-dismissed",
                    },
                    "dismissed notification remains dismissed",
                )
                if result["outcome"] != "authorization_refreshed":
                    raise AssertionError("dismissed notification case did not launch License Center")
                assert_notification_parity(python_db, dotnet_db, "dismissed notification preservation")
                state = notification_state(python_db)
                if state is None or state["state"] != "dismissed" or state["dismissed_at"] != dismissed_at:
                    raise AssertionError(f"License Center re-armed a dismissed notification: {state}")

                fake_launcher.write_text("not an executable image\n", encoding="utf-8")
                fake_launcher.chmod(0o755)
                assert_open_parity(
                    python_url,
                    dotnet_url,
                    {
                        "product_id": PRODUCT_ID,
                        "version": VERSION,
                        "installation_id": INSTALLATION_ID,
                        "correlation_id": "corr-start-failure",
                    },
                    "native launch failure fails closed",
                )
                assert_notification_parity(python_db, dotnet_db, "native launch failure")

                runtime._server = None
        finally:
            runtime_module.NativeLicenseCenterLauncher = original_launcher
            runtime._server = None
            if fake_launcher.exists():
                fake_launcher.unlink()
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            python_db.close()
            dotnet_db.close()

    print("License Center differential certification passed.")


if __name__ == "__main__":
    main()
