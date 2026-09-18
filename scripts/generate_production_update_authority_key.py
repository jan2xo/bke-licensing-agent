#!/usr/bin/env python3
"""Offline production Ed25519 update-authority key generator.

Run only on an owner-controlled operator machine. This script intentionally
refuses to write private key material inside a Git repository.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def inside_git_tree(path: Path) -> bool:
    current = path.resolve()
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument(
        "--authorization",
        required=True,
        help="Must be AUTHORIZE_OFFLINE_PRODUCTION_KEY_GENERATION",
    )
    args = parser.parse_args()

    if args.authorization != "AUTHORIZE_OFFLINE_PRODUCTION_KEY_GENERATION":
        raise SystemExit("exact production-key generation authorization token is required")

    key_id = args.key_id.strip()
    if not key_id or len(key_id) > 160 or any(
        ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
        for ch in key_id
    ):
        raise SystemExit("key ID must match [A-Za-z0-9._-]{1,160}")

    output = Path(args.output_dir).expanduser().resolve()
    if inside_git_tree(output):
        raise SystemExit(
            "refusing to write production private key material inside a Git repository"
        )

    output.mkdir(parents=True, exist_ok=False)

    private = Ed25519PrivateKey.generate()
    public = private.public_key()

    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    raw_public = public.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )

    private_path = output / "BKE-UPDATE-AUTHORITY-PRIVATE.pem"
    public_path = output / f"{key_id}.json"
    fingerprint_path = output / "PUBLIC-KEY-SHA256.txt"
    instructions_path = output / "README-PRIVATE-KEY.txt"

    private_path.write_bytes(private_pem)
    try:
        os.chmod(private_path, 0o600)
    except OSError:
        pass

    public_document = {
        "schema": "bke.update-authority-key.v1",
        "key_id": key_id,
        "algorithm": "Ed25519",
        "public_key": base64.b64encode(raw_public).decode("ascii"),
    }
    public_path.write_text(
        json.dumps(public_document, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    import hashlib

    fingerprint = hashlib.sha256(raw_public).hexdigest()
    fingerprint_path.write_text(fingerprint + "\n", encoding="ascii")
    instructions_path.write_text(
        "PRIVATE KEY HANDLING\n"
        "====================\n"
        "BKE-UPDATE-AUTHORITY-PRIVATE.pem is production private signing material.\n"
        "Do NOT commit it.\n"
        "Do NOT upload it to the Licensing Agent repository.\n"
        "Do NOT package it in an installer.\n"
        "Store it only in the approved protected Digital Solutions V2 authority boundary.\n"
        "\n"
        f"key_id={key_id}\n"
        f"public_key_sha256={fingerprint}\n",
        encoding="utf-8",
    )

    print("Production update-authority keypair generated offline.")
    print(f"key_id={key_id}")
    print(f"public_key_json={public_path}")
    print(f"private_key_pem={private_path}")
    print(f"public_key_sha256={fingerprint}")
    print("PRIVATE KEY WAS NOT PRINTED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
