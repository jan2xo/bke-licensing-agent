"""Installed machine-wide Licensing Agent runtime composition."""

from __future__ import annotations

import json
from pathlib import Path
from threading import Event, Lock

from .api.client import LicensingPlatformClient
from .api.config import ApiConfig
from .config import get_agent_port, get_platform_base_url, get_trusted_keys_dir
from .devices.fingerprint import DeviceFingerprint
from .discovery.paths import parse_discovery_paths, resolve_manifest_entry
from .discovery.scanner import scan_locations
from .licensing.authorization import AuthorizationService
from .licensing.lease import LeaseVerifier
from .licensing.license_repository import VerifiedLicenseRepository
from .licensing.service import LicensingService
from .local_api import LocalAuthorizationServer
from .manifest.validator import validate_manifest
from .storage.database import Database
from .storage.models import DiscoveredProductRecord


def _load_trusted_keys(directory: Path) -> dict[str, str]:
    keys: dict[str, str] = {}
    for path in sorted(directory.glob("*.pem")):
        if path.is_file():
            keys[path.stem] = path.read_text()
    return keys


class _LicenseKeySession:
    """Procurement activation does not require an account session."""

    @staticmethod
    def current_session() -> object:
        return object()


class _RequestInstallationIdentity:
    def __init__(self, installation_id: str):
        self.installation_id = installation_id
        self.generation = 0

    def load_or_create(self) -> str:
        return self.installation_id


class InstalledAgentRuntime:
    """Resolve product authorization from Agent-owned persisted state only."""

    def __init__(self, database: Database | None = None, port: int | None = None):
        self.database = database or Database()
        self.repository = VerifiedLicenseRepository(self.database)
        self.fingerprint = DeviceFingerprint()
        self.device_id = self.fingerprint.calculate()
        self.port = port if port is not None else get_agent_port()
        self._server: LocalAuthorizationServer | None = None
        self._stop_event = Event()
        self._discovery_lock = Lock()

    @staticmethod
    def _is_beneath(path: Path, root: Path) -> bool:
        try:
            path.resolve().relative_to(root.resolve())
            return True
        except (OSError, ValueError):
            return False

    def _refresh_discovered_products(self) -> None:
        """Synchronize the Agent-owned discovery cache with bounded roots."""
        with self._discovery_lock:
            roots = parse_discovery_paths()
            discovered = scan_locations(roots)
            current_paths = {str(item.manifest_path) for item in discovered}

            for item in discovered:
                manifest = validate_manifest(item.manifest)
                self.database.save_discovered_product(DiscoveredProductRecord.create(
                    product_id=manifest.productId,
                    display_name=manifest.displayName,
                    version=manifest.version,
                    manifest_path=item.manifest_path,
                    product_root=item.product_root,
                    entry_point_path=item.entry_point_path,
                ))

            for record in self.database.list_discovered_products():
                manifest_path = Path(record.manifest_path)
                if any(self._is_beneath(manifest_path, root) for root in roots):
                    if record.manifest_path not in current_paths:
                        self.database.delete_discovered_product(record.manifest_path)

    def _validated_product(self, product_id: str, version: str):
        matching = [
            record for record in self.database.list_discovered_products()
            if record.product_id == product_id and record.version == version
        ]
        if not matching:
            return None
        record = matching[0]
        try:
            manifest = validate_manifest(json.loads(Path(record.manifest_path).read_text()))
            entry_point = resolve_manifest_entry(manifest.entryPoint, Path(record.manifest_path).parent)
            if not entry_point.is_file():
                raise ValueError("entryPoint file does not exist")
        except Exception:
            self.database.delete_discovered_product(record.manifest_path)
            return None
        if manifest.productId != product_id or manifest.version != version:
            return None
        return manifest

    def authorize(self, request: dict[str, str]) -> dict[str, object]:
        product_id = request["product_id"]
        version = request["version"]
        installation_id = request["installation_id"]
        manifest = self._validated_product(product_id, version)
        if manifest is None:
            self._refresh_discovered_products()
            manifest = self._validated_product(product_id, version)
            if manifest is None:
                return {"authorized": False, "reason": "unknown_product_or_version"}

        binding = self.repository.active(product_id, installation_id, self.device_id)
        if binding is None:
            result: dict[str, object] = {"authorized": False, "reason": "activation_required"}
            if self._server is not None:
                result["license_center_url"] = self._server.license_center_url(product_id, version, installation_id)
            return result

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
            return {"authorized": decision.authorized, "reason": decision.reason or decision.state.value}
        except Exception:
            return {"authorized": False, "reason": "unverifiable_signed_lease"}

    def activate(self, request: dict[str, str]) -> dict[str, object]:
        product_id = request["product_id"]
        version = request["version"]
        installation_id = request["installation_id"]
        license_key = request["license_key"]
        manifest = self._validated_product(product_id, version)
        if manifest is None:
            return {"authorized": False, "reason": "invalid_product_context"}

        try:
            client = LicensingPlatformClient(ApiConfig(base_url=get_platform_base_url()))
            metadata = client.retrieve_key_metadata("")
            trusted_keys = {item.key_id: item.public_key for item in metadata.keys if item.algorithm == "Ed25519"}
            if not trusted_keys:
                return {"authorized": False, "reason": "trusted_keys_unavailable"}
            trusted_dir = get_trusted_keys_dir()
            for key_id, public_key in trusted_keys.items():
                (trusted_dir / f"{key_id}.pem").write_text(public_key)
            service = LicensingService(
                client=client,
                sessions=_LicenseKeySession(),  # type: ignore[arg-type]
                identity=_RequestInstallationIdentity(installation_id),  # type: ignore[arg-type]
                fingerprint=self.fingerprint,
            )
            decision = service.activate(manifest, license_key, LeaseVerifier(trusted_keys), self.repository)
            return {"authorized": decision.authorized, "reason": decision.reason or decision.state.value}
        except Exception:
            return {"authorized": False, "reason": "activation_failed"}

    def serve_forever(self) -> None:
        if self._stop_event.is_set():
            return
        self._refresh_discovered_products()
        if self._stop_event.is_set():
            return
        with LocalAuthorizationServer(self.authorize, self.activate, port=self.port) as server:
            self._server = server
            try:
                while not self._stop_event.wait(1):
                    pass
            except KeyboardInterrupt:
                return
            finally:
                self._server = None

    def close(self) -> None:
        self._stop_event.set()
        if self._server is not None:
            self._server.close()
            self._server = None
        self.database.close()
