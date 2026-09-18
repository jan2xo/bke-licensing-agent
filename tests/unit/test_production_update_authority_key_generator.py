from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).parents[2]
SCRIPT = ROOT / "scripts" / "generate_production_update_authority_key.py"


def test_offline_production_update_authority_generator(tmp_path: Path):
    output = tmp_path / "authority"
    process = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--key-id",
            "bke-agent-update-prod-test-v1",
            "--output-dir",
            str(output),
            "--authorization",
            "AUTHORIZE_OFFLINE_PRODUCTION_KEY_GENERATION",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert process.returncode == 0, process.stderr

    private_path = output / "BKE-UPDATE-AUTHORITY-PRIVATE.pem"
    public_path = output / "bke-agent-update-prod-test-v1.json"
    assert private_path.is_file()
    assert public_path.is_file()

    private_pem = private_path.read_text(encoding="utf-8")
    assert "PRIVATE KEY" in private_pem
    assert private_pem.strip() not in process.stdout
    assert "PRIVATE KEY WAS NOT PRINTED." in process.stdout

    document = json.loads(public_path.read_text(encoding="utf-8"))
    assert document["schema"] == "bke.update-authority-key.v1"
    assert document["key_id"] == "bke-agent-update-prod-test-v1"
    assert document["algorithm"] == "Ed25519"

    private = serialization.load_pem_private_key(private_pem.encode("utf-8"), password=None)
    assert isinstance(private, Ed25519PrivateKey)
    raw_public = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )

    import base64

    assert base64.b64decode(document["public_key"]) == raw_public


def test_generator_refuses_git_working_tree_output():
    output = ROOT / ".phase-production-key-should-never-exist"
    process = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--key-id",
            "bke-agent-update-prod-test-v1",
            "--output-dir",
            str(output),
            "--authorization",
            "AUTHORIZE_OFFLINE_PRODUCTION_KEY_GENERATION",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert process.returncode != 0
    assert "refusing to write production private key material inside a Git repository" in (
        process.stdout + process.stderr
    )
    assert not output.exists()
