"""Small local-only Agent launcher for the signed activation demonstration."""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path

from .api.client import LicensingPlatformClient
from .api.config import ApiConfig
from .devices.fingerprint import DeviceFingerprint
from .devices.identity import InstallationIdentity
from .licensing.authorization import AuthorizationService
from .licensing.lease import LeaseVerifier
from .licensing.license_repository import VerifiedLicenseRepository
from .licensing.service import LicensingService
from .local_api import LocalAuthorizationServer
from .manifest.validator import validate_manifest
from .storage.database import Database


class _Session:
    generation = 1
    def current_session(self):
        return object()


class _Identity:
    generation = 0

    def __init__(self, value: str):
        self.value = value

    def load_or_create(self):
        return self.value


class _Fingerprint:
    signals = {"platform": "local", "architecture": "local"}

    def __init__(self, value: str):
        self.value = value

    def calculate(self):
        return self.value


def _runtime(args):
    manifest = validate_manifest(json.loads(Path(args.manifest).read_text()))
    installation = _Identity(args.installation_id)
    device = _Fingerprint(hashlib.sha256(args.installation_id.encode()).hexdigest())
    database = Database(Path(args.database))
    repository = VerifiedLicenseRepository(database)
    public_key = Path(args.trusted_public_key).read_text()
    verifier = LeaseVerifier({args.key_id: public_key})
    client = LicensingPlatformClient(ApiConfig(base_url=args.platform_url, environment="local", allow_insecure_local=True, retry_count=0))
    service = LicensingService(client, _Session(), installation, device)
    return manifest, installation, device, database, repository, verifier, service


def _authorize(args, manifest, installation, device, repository, verifier):
    binding = repository.active(manifest.productId, installation.load_or_create(), device.calculate())
    if binding is None:
        return {"authorized": False, "reason": "missing_active_binding"}
    try:
        lease = repository.verify_signed_lease(binding.active_lease_id, verifier,
            product_id=manifest.productId, installation_id=installation.load_or_create(),
            device_id=device.calculate(), version=manifest.version)
        decision = AuthorizationService().authorize_from_active_binding(
            manifest, installation.load_or_create(), device.calculate(), repository,
            lambda lease_id: lease if lease_id == lease.lease_id else None)
        return {"authorized": decision.authorized, "reason": decision.reason or decision.state.value}
    except Exception:
        return {"authorized": False, "reason": "unverifiable_signed_lease"}


def main() -> int:
    parser = argparse.ArgumentParser(description="TEST/LOCAL BKE Licensing Agent demo")
    sub = parser.add_subparsers(dest="command", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--manifest", required=True)
    common.add_argument("--database", required=True)
    common.add_argument("--installation-id", required=True)
    common.add_argument("--trusted-public-key", required=True)
    common.add_argument("--key-id", required=True)
    common.add_argument("--platform-url", default="http://127.0.0.1:3000")
    activate = sub.add_parser("activate", parents=[common])
    activate.add_argument("--license-key", required=True)
    serve = sub.add_parser("serve", parents=[common])
    serve.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    manifest, installation, device, database, repository, verifier, service = _runtime(args)
    try:
        if args.command == "activate":
            decision = service.activate(manifest, args.license_key, verifier, repository)
            print(json.dumps({"testOnly": True, "authorized": decision.authorized, "reason": decision.reason or decision.state.value}))
            return 0 if decision.authorized else 1
        with LocalAuthorizationServer(lambda request: _authorize(args, manifest, installation, device, repository, verifier), port=args.port) as server:
            print(server.url, flush=True)
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        return 0
    finally:
        database.close()


if __name__ == "__main__":
    raise SystemExit(main())
