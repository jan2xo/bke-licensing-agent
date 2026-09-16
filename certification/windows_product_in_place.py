"""Disposable Windows certification for the real privileged product updater.

This proves the installed-Agent update composition together with the pinned
Updater Core helper. It never targets a production installation.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import shutil
import subprocess
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from bke_updater_core.models import ProductManifest

from bke_licensing_agent.updates.orchestrator import UPDATE_PACKAGE_CONTENT_TYPE, UpdateOrchestrator
from bke_licensing_agent.updates.privileged_runtime import AgentPrivilegedRuntimeConfig

PRODUCT_ID = "bke-updater-certification"
PLATFORM = "windows"
ARCHITECTURE = "x64"
CHANNEL = "stable"
ENTRY_POINT = "BKE.Update.Probe.exe"
READY_MARKER = "BKE_UPDATER_READY"


def _canonical(document: dict[str, object]) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _raw_private(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())


def _raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _sign(unsigned: dict[str, object], key: Ed25519PrivateKey) -> dict[str, object]:
    document = dict(unsigned)
    document["signature"] = base64.b64encode(key.sign(_canonical(unsigned))).decode("ascii")
    return document


def _copy_probe(source: Path, destination: Path, version: str, *, broken: bool = False, obsolete: bool = False) -> None:
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination)
    (destination / "version.txt").write_text(version, encoding="utf-8")
    (destination / "mode.txt").write_text("broken" if broken else "ready", encoding="utf-8")
    if obsolete:
        (destination / "obsolete-runtime.dll").write_bytes(b"old-runtime-that-must-disappear")


def _zip_tree(source: Path, destination: Path) -> None:
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(source).as_posix())


def _update_policy(
    key: Ed25519PrivateKey,
    artifact: Path,
    *,
    current_version: str,
    latest_version: str,
    revision: int,
    release_id: str,
) -> dict[str, object]:
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    unsigned: dict[str, object] = {
        "schema": "bke.update-policy.v1",
        "product_id": PRODUCT_ID,
        "current_version": current_version,
        "latest_version": latest_version,
        "minimum_supported_version": current_version,
        "channel": CHANNEL,
        "platform": PLATFORM,
        "architecture": ARCHITECTURE,
        "release_id": release_id,
        "artifact_id": f"{release_id}-windows-x64",
        "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "artifact_size": artifact.stat().st_size,
        "content_type": UPDATE_PACKAGE_CONTENT_TYPE,
        "published_at": now,
        "issued_at": now,
        "revision": revision,
        "signing_key_id": "digital-certification",
        "algorithm": "Ed25519",
    }
    return _sign(unsigned, key)


def _target_policy(key: Ed25519PrivateKey, install_root: Path) -> dict[str, object]:
    unsigned: dict[str, object] = {
        "schema": "bke.install-target-policy.v1",
        "policy_id": "bke-updater-certification-windows-x64-v1",
        "revision": 1,
        "product_id": PRODUCT_ID,
        "platform": PLATFORM,
        "architecture": ARCHITECTURE,
        "install_root": str(install_root.resolve()),
        "entry_point": ENTRY_POINT,
        "signing_key_id": "bke-target-certification",
        "algorithm": "Ed25519",
    }
    return _sign(unsigned, key)


def _manifest(install_root: Path, version: str) -> ProductManifest:
    return ProductManifest(
        PRODUCT_ID,
        version,
        PLATFORM,
        ARCHITECTURE,
        ENTRY_POINT,
        install_root,
        update_channel=CHANNEL,
        health_check=READY_MARKER,
    )


def _helper_state(runtime_root: Path, transaction_id: str) -> dict[str, object]:
    path = runtime_root / "transactions" / transaction_id / "state.json"
    if not path.is_file():
        raise AssertionError(f"missing helper transaction state: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe-publish", type=Path, required=True)
    parser.add_argument("--helper", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    args = parser.parse_args()

    probe = args.probe_publish.resolve()
    helper = args.helper.resolve()
    root = args.work_root.resolve()
    if not (probe / ENTRY_POINT).is_file():
        raise SystemExit(f"probe entry point missing: {probe / ENTRY_POINT}")
    if not helper.is_file():
        raise SystemExit(f"Updater Core helper missing: {helper}")

    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)

    approved_root = root / "products"
    install_root = approved_root / "BKE Update Probe"
    payload_root = root / "payloads"
    runtime_root = root / "agent-runtime"
    state_root = root / "agent-state"
    external_data = root / "user-data" / "customer-project.txt"
    approved_root.mkdir(parents=True)
    payload_root.mkdir(parents=True)
    external_data.parent.mkdir(parents=True)
    external_data.write_text("customer-data-must-survive", encoding="utf-8")

    v1 = payload_root / "v1"
    v2 = payload_root / "v2"
    v3 = payload_root / "v3-broken"
    _copy_probe(probe, v1, "1.0.0", obsolete=True)
    _copy_probe(probe, v2, "2.0.0")
    _copy_probe(probe, v3, "3.0.0", broken=True)
    shutil.copytree(v1, install_root)

    v2_zip = payload_root / "v2.update.zip"
    v3_zip = payload_root / "v3-broken.update.zip"
    _zip_tree(v2, v2_zip)
    _zip_tree(v3, v3_zip)

    agent_key = Ed25519PrivateKey.generate()
    digital_key = Ed25519PrivateKey.generate()
    target_key = Ed25519PrivateKey.generate()

    config = AgentPrivilegedRuntimeConfig(
        runtime_root=runtime_root,
        helper_executable=helper,
        signing_key_id="agent-certification",
        signing_private_key=_raw_private(agent_key),
        trusted_digital_keys={"digital-certification": _raw_public(digital_key)},
        trusted_bke_keys={"bke-target-certification": _raw_public(target_key)},
        approved_install_roots=(str(approved_root.resolve()),),
        expected_channel=CHANNEL,
    )
    target_policy = _target_policy(target_key, install_root)
    orchestrator = UpdateOrchestrator(
        {"digital-certification": _raw_public(digital_key)},
        state_root,
    )

    def run_helper(command) -> None:
        subprocess.run(tuple(command), check=True)

    # 1. Successful whole-tree v1 -> v2 replacement.
    raw_v2 = _update_policy(
        digital_key,
        v2_zip,
        current_version="1.0.0",
        latest_version="2.0.0",
        revision=1,
        release_id="release-v2",
    )
    verified_v2 = orchestrator.verify_policy(raw_v2, _manifest(install_root, "1.0.0"))
    result = orchestrator.execute_privileged_update(
        _manifest(install_root, "1.0.0"),
        verified_v2,
        v2_zip,
        privileged_config=config,
        target_policy=target_policy,
        elevate=run_helper,
    )
    assert result.value == "STAGED"
    time.sleep(2)
    assert (install_root / "version.txt").read_text(encoding="utf-8") == "2.0.0"
    assert not (install_root / "obsolete-runtime.dll").exists(), "whole-tree update left obsolete runtime content"
    assert external_data.read_text(encoding="utf-8") == "customer-data-must-survive"
    committed_id = f"{PRODUCT_ID}-release-v2-1"
    committed = _helper_state(runtime_root, committed_id)
    assert committed["state"] == "COMMITTED", committed

    # 2. Broken v3 must roll back to the complete v2 tree.
    raw_v3 = _update_policy(
        digital_key,
        v3_zip,
        current_version="2.0.0",
        latest_version="3.0.0",
        revision=2,
        release_id="release-v3-broken",
    )
    verified_v3 = orchestrator.verify_policy(raw_v3, _manifest(install_root, "2.0.0"))
    try:
        orchestrator.execute_privileged_update(
            _manifest(install_root, "2.0.0"),
            verified_v3,
            v3_zip,
            privileged_config=config,
            target_policy=target_policy,
            elevate=run_helper,
        )
    except subprocess.CalledProcessError:
        pass
    else:
        raise AssertionError("broken update unexpectedly succeeded")

    time.sleep(2)
    assert (install_root / "version.txt").read_text(encoding="utf-8") == "2.0.0", "rollback did not restore v2"
    assert (install_root / "mode.txt").read_text(encoding="utf-8") == "ready"
    assert external_data.read_text(encoding="utf-8") == "customer-data-must-survive"
    rolled_back_id = f"{PRODUCT_ID}-release-v3-broken-2"
    rolled_back = _helper_state(runtime_root, rolled_back_id)
    assert rolled_back["state"] == "ROLLED_BACK", rolled_back

    evidence = {
        "product_id": PRODUCT_ID,
        "successful_update": "1.0.0 -> 2.0.0",
        "successful_transaction": committed["state"],
        "obsolete_install_content_removed": True,
        "failed_update": "2.0.0 -> 3.0.0",
        "failed_transaction": rolled_back["state"],
        "restored_version": (install_root / "version.txt").read_text(encoding="utf-8"),
        "external_customer_data_preserved": True,
        "helper": str(helper),
    }
    evidence_path = root / "windows-product-in-place-evidence.json"
    evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
