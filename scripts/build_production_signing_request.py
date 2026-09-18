#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path

SHA256 = re.compile(r"^[a-f0-9]{64}$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a fail-closed production signing request from Phase 11 preflight evidence.")
    parser.add_argument("manifest")
    parser.add_argument("output")
    args = parser.parse_args()

    source = Path(args.manifest)
    document = json.loads(source.read_text(encoding="utf-8-sig"))

    require(document.get("schema") == "bke.production-release-preflight.v1", "unexpected preflight schema")
    require(document.get("status") == "PASS", "preflight did not pass")
    require(document.get("production_ready") is False, "preflight unexpectedly claims production readiness")
    require(document.get("signing_state") == "NOT_SIGNED", "signing request must start from unsigned installer bytes")
    require(document.get("production_update_authority") == "NOT_ACTIVATED", "production update authority is already active")
    require(document.get("production_catalog_publication") == "NOT_AUTHORIZED", "production catalog publication is already authorized")
    require(document.get("production_deployment") == "NOT_AUTHORIZED", "production deployment is already authorized")
    require(set(document.get("architectures", [])) == {"x64", "arm64"}, "expected exactly x64 + arm64 release architectures")

    installers = document.get("installers")
    require(isinstance(installers, dict), "installer evidence is missing")

    requested = []
    for architecture in ("x64", "arm64"):
        item = installers.get(architecture)
        require(isinstance(item, dict), f"{architecture} installer evidence is missing")
        filename = item.get("file")
        digest = item.get("sha256")
        size = item.get("bytes")
        authenticode = item.get("authenticode_status")
        require(isinstance(filename, str) and filename.endswith(".exe"), f"{architecture} filename is invalid")
        require(isinstance(digest, str) and SHA256.fullmatch(digest) is not None, f"{architecture} SHA-256 is invalid")
        require(isinstance(size, int) and size > 0, f"{architecture} byte size is invalid")
        require(authenticode != "Valid", f"{architecture} installer is already Authenticode-valid; do not reuse unsigned signing request")

        requested.append(
            {
                "architecture": architecture,
                "file": filename,
                "unsigned_sha256": digest,
                "unsigned_bytes": size,
                "pre_sign_authenticode_status": authenticode,
            }
        )

    result = {
        "schema": "bke.production-signing-request.v1",
        "source_sha": document["source_sha"],
        "version": document["version"],
        "artifacts": requested,
        "windows_signing": {
            "required": True,
            "approved_signer_subject": None,
            "approved_signer_thumbprint": None,
            "authorization_state": "OWNER_AUTHORIZATION_REQUIRED",
        },
        "update_authority": {
            "required": True,
            "production_key_id": None,
            "authorization_state": "OWNER_AUTHORIZATION_REQUIRED",
        },
        "post_sign_requirements": [
            "Authenticode status Valid for x64",
            "Authenticode status Valid for arm64",
            "recompute signed SHA-256 and byte sizes",
            "generate bke.production-release-manifest.v1",
            "do not reuse unsigned hashes as signed release hashes",
        ],
        "production_catalog_publication": "NOT_AUTHORIZED",
        "production_deployment": "NOT_AUTHORIZED",
        "signing_authorized": False,
        "publish_allowed": False,
    }

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
