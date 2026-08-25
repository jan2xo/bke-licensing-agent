#!/usr/bin/env python3
"""Create a release-signable bke.bundle-policy.v1 envelope from exact binaries.

The private key is supplied externally. This tool never generates, stores, or
prints a private key and is intended for controlled release CI or an offline
signing workstation.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_payload(*, policy_id: str, source_product_id: str, source_version: str,
                  source_entry_point: str, source_binary: Path,
                  target_product_id: str, target_version: str,
                  target_entry_point: str, target_binary: Path) -> bytes:
    data = {
        "schema": "bke.bundle-policy.v1",
        "policy_id": policy_id,
        "source": {
            "product_id": source_product_id,
            "version": source_version,
            "entry_point": source_entry_point.replace("\\", "/"),
            "sha256": _sha256(source_binary),
        },
        "target": {
            "product_id": target_product_id,
            "version": target_version,
            "entry_point": target_entry_point.replace("\\", "/"),
            "sha256": _sha256(target_binary),
        },
    }
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_payload(payload: bytes, *, key_id: str, private_key_pem: bytes) -> dict[str, str]:
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("bundle policy signing key must be Ed25519")
    return {
        "payload": base64.b64encode(payload).decode("ascii"),
        "signature": base64.b64encode(key.sign(payload)).decode("ascii"),
        "key_id": key_id,
        "algorithm": "Ed25519",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Sign a BKE enterprise bundle policy")
    parser.add_argument("--policy-id", required=True)
    parser.add_argument("--source-product-id", required=True)
    parser.add_argument("--source-version", required=True)
    parser.add_argument("--source-entry-point", required=True)
    parser.add_argument("--source-binary", type=Path, required=True)
    parser.add_argument("--target-product-id", required=True)
    parser.add_argument("--target-version", required=True)
    parser.add_argument("--target-entry-point", required=True)
    parser.add_argument("--target-binary", type=Path, required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    for binary in (args.source_binary, args.target_binary):
        if not binary.is_file():
            parser.error(f"binary not found: {binary}")
    if not args.private_key.is_file():
        parser.error(f"private key not found: {args.private_key}")

    payload = build_payload(
        policy_id=args.policy_id,
        source_product_id=args.source_product_id,
        source_version=args.source_version,
        source_entry_point=args.source_entry_point,
        source_binary=args.source_binary,
        target_product_id=args.target_product_id,
        target_version=args.target_version,
        target_entry_point=args.target_entry_point,
        target_binary=args.target_binary,
    )
    envelope = sign_payload(payload, key_id=args.key_id,
                            private_key_pem=args.private_key.read_bytes())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(envelope, sort_keys=True, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
