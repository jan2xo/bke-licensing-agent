"""Installed machine-wide Licensing Agent runtime composition."""

from __future__ import annotations

import json
import time
from pathlib import Path

from .config import get_agent_port, get_trusted_keys_dir
from .devices.fingerprint import DeviceFingerprint
from .licensing.authorization import AuthorizationService
from .licensing.lease import LeaseVerifier
from .licensing.license_repository import VerifiedLicenseRepository
from .local_api import LocalAuthorizationServer
from .manifest.validator import validate_manifest
from .storage.database import Database


def _load_trusted_keys(directory: Path) -> dict[str, str]:
    keys: dict[str, str] = {}
    for path in sorted(directory.glob("*.pem")):
        if path.is_file():
            keys[path.stem] = path.read_text()
    return keys


class InstalledAgentRuntime:
    """Resolve product authorization from Agent-owned persisted state only."""

    def __init__(self, database: Database | None = None, port: int | None = None):
        self.database = database or Database()
        self.repository = VerifiedLicenseRepository(self.database)
        self.device_id = DeviceFingerprint().calculate()
        self.port = port if port is not None else get_agent_port()
        self._server: LocalAuthorizationServer | None = None

    def authorize(self, request: dict[str, str]) -> dict[str, object]:
        product_id = request["product_id"]
        version = request["version"]
        installation_id = request["installation_id"]

        matching = [
            record for record in self.database.list_discovered_products()
            if record.product_id == product_id and record.version == version
        ]
        if not matching:
            return {"authorized": False, "reason": "unknown_product_or_version"}

        record = matching[0]
        try:
            manifest = validate_manifest(json.loads(Path(record.manifest_path).read_text()))
        except Exception:
            return {"authorized": False, "reason": "invalid_product_manifest"}
        if manifest.productId != product_id or manifest.version != version:
            return {"authorized": False, "reason": "product_context_mismatch"}

        binding = self.repository.active(product_id, installation_id, self.device_id)
        if binding is None:
            return {"authorized": False, "reason": "missing_active_binding"}

        keys = _load_trusted_keys(get_trusted_keys_dir())
        if not keys:
            return {"authorized": False, "reason": "trusted_keys_unavailable"}

        try:
            verifier = LeaseVerifier(keys)
            lease = self.repository.verify_signed_lease(
                binding.active_lease_id,
                verifier,
                product_id=product_id,
                installation_id=installation_id,
                device_id=self.device_id,
                version=version,
            )
            decision = AuthorizationService().authorize_from_active_binding(
                manifest,
                installation_id,
                self.device_id,
                self.repository,
                lambda lease_id: lease if lease_id == lease.lease_id else None,
            )
            return {
                "authorized": decision.authorized,
                "reason": decision.reason or decision.state.value,
            }
        except Exception:
            return {"authorized": False, "reason": "unverifiable_signed_lease"}

    def serve_forever(self) -> None:
        with LocalAuthorizationServer(self.authorize, port=self.port) as server:
            self._server = server
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                return
            finally:
                self._server = None

    def close(self) -> None:
        if self._server is not None:
            self._server.close()
            self._server = None
        self.database.close()
