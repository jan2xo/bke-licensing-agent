#!/usr/bin/env python3
"""Sign a strict bke.install-target-policy.v1 document with an external Ed25519 key.

The private key is supplied by the caller and is never generated, stored, or printed
by this tool. CI may use a disposable key for proof artifacts; customer/production
packages must use an owner-controlled persistent BKE target-signing key.
"""
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _canonical(document: dict[str, object]) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def build_unsigned_policy(
    *,
    policy_id: str,
    revision: int,
    product_id: str,
    platform: str,
    architecture: str,
    install_root: str,
    entry_point: str,
    signing_key_id: str,
) -> dict[str, object]:
    if revision < 1:
        raise ValueError("revision must be >= 1")
    return {
        "schema": "bke.install-target-policy.v1",
        "policy_id": policy_id,
        "revision": revision,
        "product_id": product_id,
        "platform": platform,
        "architecture": architecture,
        "install_root": install_root,
        "entry_point": entry_point,
        "signing_key_id": signing_key_id,
        "algorithm": "Ed25519",
    }


def sign_policy(unsigned: dict[str, object], private_key_pem: bytes) -> dict[str, object]:
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("install-target signing key must be Ed25519")
    document = dict(unsigned)
    document["signature"] = base64.b64encode(key.sign(_canonical(unsigned))).decode("ascii")
    return document


def main() -> int:
    parser = argparse.ArgumentParser(description="Sign a BKE install-target policy")
    parser.add_argument("--policy-id", required=True)
    parser.add_argument("--revision", type=int, required=True)
    parser.add_argument("--product-id", required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--architecture", required=True)
    parser.add_argument("--install-root", required=True)
    parser.add_argument("--entry-point", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    if not args.private_key.is_file():
        parser.error(f"private key not found: {args.private_key}")

    unsigned = build_unsigned_policy(
        policy_id=args.policy_id,
        revision=args.revision,
        product_id=args.product_id,
        platform=args.platform,
        architecture=args.architecture,
        install_root=args.install_root,
        entry_point=args.entry_point,
        signing_key_id=args.key_id,
    )
    document = sign_policy(unsigned, args.private_key.read_bytes())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
