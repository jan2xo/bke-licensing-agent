"""Certify real Air Stack and Render Dock updater packages against the Agent.

The product repositories build the exact updater ZIPs. This lane proves those ZIPs
pass Agent signed staging/handoff and perform whole-tree replacement on disposable
Windows install roots. GUI launch/readiness/rollback is certified separately by
windows_product_in_place.py using the frozen production helper.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from bke_updater_core.helper.main import replace_and_launch
from bke_updater_core.helper.protocol import HelperPlan
from bke_updater_core.models import ProductManifest

from bke_licensing_agent.updates.orchestrator import UPDATE_PACKAGE_CONTENT_TYPE, UpdateOrchestrator
from bke_licensing_agent.updates.privileged_runtime import AgentPrivilegedRuntimeConfig

CHANNEL = "stable"
CURRENT_VERSION = "0"


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


def _load_package(directory: Path) -> tuple[Path, dict[str, object]]:
    metadata_files = sorted(directory.glob("*.update.json"))
    payload_files = sorted(directory.glob("*.update.zip"))
    if len(metadata_files) != 1 or len(payload_files) != 1:
        raise AssertionError(f"expected exactly one updater metadata file and ZIP in {directory}")
    metadata = json.loads(metadata_files[0].read_text(encoding="utf-8-sig"))
    payload = payload_files[0]
    required = {
        "schema", "productId", "version", "platform", "architecture",
        "entryPoint", "filename", "contentType", "bytes", "sha256",
    }
    if set(metadata) != required:
        raise AssertionError(f"unexpected updater metadata fields for {directory}: {sorted(metadata)}")
    if metadata["schema"] != "bke.update-package.v1":
        raise AssertionError("unsupported product updater package schema")
    if metadata["contentType"] != UPDATE_PACKAGE_CONTENT_TYPE:
        raise AssertionError("product updater package content type mismatch")
    if metadata["filename"] != payload.name:
        raise AssertionError("product updater metadata filename mismatch")
    if metadata["bytes"] != payload.stat().st_size:
        raise AssertionError("product updater metadata size mismatch")
    if metadata["sha256"] != hashlib.sha256(payload.read_bytes()).hexdigest():
        raise AssertionError("product updater metadata hash mismatch")
    if metadata["platform"] != "windows" or metadata["architecture"] != "x64":
        raise AssertionError("product updater package is not Windows x64")
    return payload, metadata


def _update_policy(
    key: Ed25519PrivateKey,
    payload: Path,
    metadata: dict[str, object],
    *,
    revision: int,
) -> dict[str, object]:
    product_id = str(metadata["productId"])
    latest_version = str(metadata["version"])
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    unsigned: dict[str, object] = {
        "schema": "bke.update-policy.v1",
        "product_id": product_id,
        "current_version": CURRENT_VERSION,
        "latest_version": latest_version,
        "minimum_supported_version": CURRENT_VERSION,
        "channel": CHANNEL,
        "platform": "windows",
        "architecture": "x64",
        "release_id": f"cert-{product_id}-{latest_version}",
        "artifact_id": f"cert-{product_id}-{latest_version}-windows-x64",
        "artifact_sha256": hashlib.sha256(payload.read_bytes()).hexdigest(),
        "artifact_size": payload.stat().st_size,
        "content_type": UPDATE_PACKAGE_CONTENT_TYPE,
        "published_at": now,
        "issued_at": now,
        "revision": revision,
        "signing_key_id": "digital-product-certification",
        "algorithm": "Ed25519",
    }
    return _sign(unsigned, key)


def _target_policy(
    key: Ed25519PrivateKey,
    metadata: dict[str, object],
    install_root: Path,
    *,
    revision: int,
) -> dict[str, object]:
    product_id = str(metadata["productId"])
    unsigned: dict[str, object] = {
        "schema": "bke.install-target-policy.v1",
        "policy_id": f"cert-{product_id}-windows-x64",
        "revision": revision,
        "product_id": product_id,
        "platform": "windows",
        "architecture": "x64",
        "install_root": str(install_root.resolve()),
        "entry_point": str(metadata["entryPoint"]),
        "signing_key_id": "bke-product-target-certification",
        "algorithm": "Ed25519",
    }
    return _sign(unsigned, key)


def _argument(command: tuple[str, ...], name: str) -> Path:
    try:
        index = command.index(name)
    except ValueError as exc:
        raise AssertionError(f"privileged command missing {name}") from exc
    if index + 1 >= len(command):
        raise AssertionError(f"privileged command missing value for {name}")
    return Path(command[index + 1])


def _fingerprint(root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            result[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def _certify_one(
    package_dir: Path,
    helper: Path,
    work_root: Path,
    *,
    revision: int,
) -> dict[str, object]:
    payload, metadata = _load_package(package_dir)
    product_id = str(metadata["productId"])
    version = str(metadata["version"])
    entry_point = str(metadata["entryPoint"])

    product_root = work_root / product_id
    approved_root = product_root / "products"
    install_root = approved_root / product_id
    runtime_root = product_root / "agent-runtime"
    state_root = product_root / "agent-state"
    external_data = product_root / "customer-data" / "preserve-me.txt"
    backup_root = runtime_root / "product-backups" / product_id
    approved_root.mkdir(parents=True, exist_ok=True)
    install_root.mkdir(parents=True, exist_ok=True)
    external_data.parent.mkdir(parents=True, exist_ok=True)
    backup_root.parent.mkdir(parents=True, exist_ok=True)
    external_data.write_text("customer-data-must-survive", encoding="utf-8")
    (install_root / "obsolete-bke-runtime.dll").write_bytes(b"obsolete-file-that-must-be-cleaned")

    agent_key = Ed25519PrivateKey.generate()
    digital_key = Ed25519PrivateKey.generate()
    target_key = Ed25519PrivateKey.generate()
    config = AgentPrivilegedRuntimeConfig(
        runtime_root=runtime_root,
        helper_executable=helper,
        signing_key_id="agent-product-certification",
        signing_private_key=_raw_private(agent_key),
        trusted_digital_keys={"digital-product-certification": _raw_public(digital_key)},
        trusted_bke_keys={"bke-product-target-certification": _raw_public(target_key)},
        approved_install_roots=(str(approved_root.resolve()),),
        expected_channel=CHANNEL,
    )

    manifest = ProductManifest(
        product_id,
        CURRENT_VERSION,
        "windows",
        "x64",
        entry_point,
        install_root,
        update_channel=CHANNEL,
    )
    orchestrator = UpdateOrchestrator(
        {"digital-product-certification": _raw_public(digital_key)},
        state_root,
    )
    raw_policy = _update_policy(digital_key, payload, metadata, revision=revision)
    verified_policy = orchestrator.verify_policy(raw_policy, manifest)
    target_policy = _target_policy(target_key, metadata, install_root, revision=revision)

    captured: list[tuple[str, ...]] = []
    result = orchestrator.execute_privileged_update(
        manifest,
        verified_policy,
        payload,
        privileged_config=config,
        target_policy=target_policy,
        elevate=lambda command: captured.append(tuple(command)),
    )
    if result.value != "STAGED" or len(captured) != 1:
        raise AssertionError(f"Agent did not stage exactly one privileged product update for {product_id}")

    command = captured[0]
    for required in ("--privileged-update", "--request", "--update-policy", "--target-policy", "--artifact", "--staged-root"):
        if required not in command:
            raise AssertionError(f"signed privileged handoff missing {required} for {product_id}")
    if "--install-root" in command or "--executable" in command:
        raise AssertionError("caller-selected product authority leaked into privileged command")

    staged_root = _argument(command, "--staged-root").resolve()
    if not (staged_root / entry_point).is_file():
        raise AssertionError(f"real product payload entry point missing after Agent staging: {entry_point}")
    staged_fingerprint = _fingerprint(staged_root)
    if not staged_fingerprint:
        raise AssertionError("real product payload staged no files")

    helper_transactions = product_root / "helper-transactions"
    transaction_id = f"real-product-{product_id}-{version}"
    plan = HelperPlan(
        install_root=install_root,
        staged_root=staged_root,
        backup_root=backup_root,
        executable=install_root / entry_point,
        launch=False,
        transaction_root=helper_transactions,
        transaction_id=transaction_id,
    )
    if replace_and_launch(plan) != 0:
        raise AssertionError(f"whole-tree product replacement failed for {product_id}")

    if (install_root / "obsolete-bke-runtime.dll").exists():
        raise AssertionError(f"obsolete BKE install content survived replacement for {product_id}")
    if external_data.read_text(encoding="utf-8") != "customer-data-must-survive":
        raise AssertionError(f"external customer data changed during {product_id} replacement")
    if _fingerprint(install_root) != staged_fingerprint:
        raise AssertionError(f"installed {product_id} tree differs from the staged real product payload")

    helper_state = json.loads(
        (helper_transactions / transaction_id / "state.json").read_text(encoding="utf-8")
    )
    if helper_state["state"] != "COMMITTED":
        raise AssertionError(f"helper did not commit real product replacement for {product_id}")

    return {
        "product_id": product_id,
        "version": version,
        "entry_point": entry_point,
        "payload": payload.name,
        "payload_sha256": str(metadata["sha256"]),
        "payload_bytes": int(metadata["bytes"]),
        "installed_file_count": len(staged_fingerprint),
        "agent_signed_handoff": True,
        "caller_selected_install_authority_absent": True,
        "whole_tree_replacement": helper_state["state"],
        "obsolete_bke_content_removed": True,
        "external_customer_data_preserved": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package-dir", type=Path, action="append", required=True)
    parser.add_argument("--helper", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()

    helper = args.helper.resolve()
    if not helper.is_file():
        raise SystemExit(f"Updater Core helper missing: {helper}")
    work_root = args.work_root.resolve()
    if work_root.exists():
        shutil.rmtree(work_root)
    work_root.mkdir(parents=True)

    results = [
        _certify_one(directory.resolve(), helper, work_root, revision=index)
        for index, directory in enumerate(args.package_dir, start=1)
    ]
    product_ids = [item["product_id"] for item in results]
    if len(product_ids) != len(set(product_ids)):
        raise AssertionError("duplicate product package supplied to certification")

    evidence = {
        "schema": "bke.real-product-in-place-certification.v1",
        "products": results,
        "note": "GUI launch/readiness and forced rollback are certified by the separate frozen-helper Windows product in-place lane.",
    }
    args.evidence.parent.mkdir(parents=True, exist_ok=True)
    args.evidence.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
