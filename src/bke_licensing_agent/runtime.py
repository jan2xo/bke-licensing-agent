"""Installed machine-wide Licensing Agent runtime composition."""

from __future__ import annotations

import json
import os
import time
import uuid
import threading
from pathlib import Path

from .api.client import LicensingPlatformClient
from .api.config import ApiConfig
from .config import (
    get_agent_port,
    get_bundle_policies_dir,
    get_platform_base_url,
    get_trusted_keys_dir,
)
from .devices.fingerprint import DeviceFingerprint
from .discovery.scanner import scan as discovery_scan
from .execution.module_launch import (
    BundlePolicy,
    EnterpriseModuleLaunchService,
    ModuleLaunchDenied,
    SignedBundlePolicyVerifier,
)
from .execution.module_pipe import (
    EnterpriseModulePipeDispatcher,
    ModuleLaunchContext,
    ModuleLaunchPipeServer,
)
from .execution.service import ArtifactMetadata, LaunchExecutionService
from .licensing.authorization import AuthorizationService
from .licensing.launch_authorization import (
    AuthorizationDecision as LaunchAuthorizationDecision,
    AuthorizationReason as LaunchAuthorizationReason,
)
from .licensing.lease import LeaseVerifier
from .licensing.license_repository import VerifiedLicenseRepository
from .licensing.service import LicensingService
from .local_api import LocalAuthorizationServer
from .license_center.native_launcher import NativeLicenseCenterLauncher
from .license_center.service import LicenseCenterAction, LicenseCenterService, OpenLicenseCenterRequest
from .manifest.validator import validate_manifest
from .storage.database import Database
from .storage.models import DiscoveredProductRecord
from .updates.discovery import UpdateDiscoveryCoordinator
from .updates.installed_privileged import execute_installed_product_update


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

    def __init__(self, database: Database | None = None, port: int | None = None,
                 module_server: ModuleLaunchPipeServer | None = None):
        self.database = database or Database()
        self.repository = VerifiedLicenseRepository(self.database)
        self.fingerprint = DeviceFingerprint()
        self.device_id = self.fingerprint.calculate()
        self.port = port if port is not None else get_agent_port()
        self._server: LocalAuthorizationServer | None = None
        self._module_server = module_server
        self._update_stop = threading.Event()
        self._update_thread: threading.Thread | None = None
        self.update_discovery = UpdateDiscoveryCoordinator(
            state_root=self.database.path.parent / "updates",
            platform_client=LicensingPlatformClient(ApiConfig(base_url=get_platform_base_url())),
            trusted_keys=lambda: _load_trusted_keys(get_trusted_keys_dir()),
            resolve_product=lambda product_id, version: self._validated_product_record(product_id, version),
            resolve_lease=self._update_lease,
        )
        if self._module_server is None and os.name == "nt":
            self._refresh_discovery()
            self._module_server = self._build_module_server()

    def _update_lease(self, product_id: str, version: str):
        for record in self.repository.list_for_product(product_id):
            if (record.product_version == version and record.status == "verified" and
                    record.signed_payload and record.signed_signature and record.signed_algorithm):
                return record
        return None

    def _refresh_updates_background(self) -> None:
        if self._update_stop.wait(self.update_discovery.policy.initial_delay_seconds):
            return
        while not self._update_stop.is_set():
            for record in self.database.list_discovered_products():
                if self._update_stop.is_set():
                    return
                if self.update_discovery.refresh_due(record.product_id, record.version):
                    self.update_discovery.refresh(record.product_id, record.version)
            self._update_stop.wait(self.update_discovery.next_delay())

    def request_update_refresh(self, product_id: str, version: str) -> dict[str, object]:
        if self._validated_product_record(product_id, version) is None:
            return {"state": "refresh_failed", "product_id": product_id, "current_version": version}
        queued = self.update_discovery.queue_refresh(product_id, version)
        return {"state": "refresh_queued" if queued else "refresh_already_queued",
                "product_id": product_id, "current_version": version}

    def dismiss_update(self, product_id: str, version: str, latest_version: str) -> dict[str, object]:
        if self._validated_product_record(product_id, version) is None:
            return {"state": "dismiss_rejected", "product_id": product_id, "current_version": version}
        return self.update_discovery.dismiss(product_id, version, latest_version)

    def product_update_status(self, product_id: str, version: str = "") -> dict[str, object]:
        candidates = [record for record in self.database.list_discovered_products()
                      if record.product_id == product_id and (not version or record.version == version)]
        if not candidates:
            result: dict[str, object] = {"state": "never_checked", "product_id": product_id}
            if version:
                result["current_version"] = version
            return result
        selected = sorted(candidates, key=lambda item: item.discovered_at, reverse=True)[0]
        return self.update_discovery.status(selected.product_id, selected.version)

    def open_update_center(self, request: dict[str, str]) -> dict[str, object]:
        product_id, version = request["product_id"], request["version"]
        status = self.update_discovery.status(product_id, version, apply_suppression=False)
        correlation_id = request.get("correlation_id") or str(uuid.uuid4())
        if status.get("state") not in {"update_available", "stale_update"}:
            return {"outcome": "no_update", "reason": str(status.get("state", "never_checked")),
                    "correlation_id": correlation_id}
        try:
            state = execute_installed_product_update(self, product_id, version)
        except Exception:
            return {"outcome": "update_failed", "reason": "privileged_update_verification_or_handoff_failed",
                    "correlation_id": correlation_id}
        return {"outcome": "update_started", "reason": state.value.lower(), "correlation_id": correlation_id}

    def _refresh_discovery(self) -> None:
        """Refresh trusted discovery metadata from configured install roots.

        Discovery never grants authorization. It only gives the Agent canonical
        manifest/root/entry-point locations that are later bound to signed lease
        and signed bundle-policy checks.
        """
        try:
            discovered = discovery_scan()
        except Exception:
            return
        for product in discovered:
            try:
                validated = validate_manifest(product.manifest)
                self.database.save_discovered_product(DiscoveredProductRecord.create(
                    product_id=validated.productId,
                    display_name=validated.displayName,
                    version=validated.version,
                    manifest_path=product.manifest_path,
                    product_root=product.product_root,
                    entry_point_path=product.entry_point_path,
                ))
            except Exception:
                continue

    def _validated_product_record(self, product_id: str, version: str, *, refresh_on_miss: bool = True):
        matching = [
            record for record in self.database.list_discovered_products()
            if record.product_id == product_id and record.version == version
        ]
        if not matching and refresh_on_miss and os.name == "nt":
            self._refresh_discovery()
            return self._validated_product_record(product_id, version, refresh_on_miss=False)
        if not matching:
            return None
        record = matching[0]
        try:
            manifest = validate_manifest(json.loads(Path(record.manifest_path).read_text()))
        except Exception:
            return None
        if manifest.productId != product_id or manifest.version != version:
            return None
        if Path(record.entry_point_path).resolve() != (Path(record.product_root).resolve() / manifest.entryPoint).resolve():
            return None
        return record, manifest

    def _validated_product(self, product_id: str, version: str):
        resolved = self._validated_product_record(product_id, version)
        return resolved[1] if resolved is not None else None

    def _verified_local_authorization(self, product_id: str, version: str,
                                      installation_id: str):
        manifest = self._validated_product(product_id, version)
        if manifest is None:
            return manifest, None
        binding = self.repository.active(product_id, installation_id, self.device_id)
        if binding is None:
            return manifest, None
        keys = _load_trusted_keys(get_trusted_keys_dir())
        if not keys:
            return manifest, None
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
            return manifest, decision
        except Exception:
            return manifest, None

    def _ensure_module_server(self) -> None:
        if os.name != "nt" or self._module_server is not None:
            return
        self._refresh_discovery()
        server = self._build_module_server()
        if server is None:
            return
        self._module_server = server
        if self._server is not None:
            self._module_server.start()

    def authorize(self, request: dict[str, str]) -> dict[str, object]:
        product_id = request["product_id"]
        version = request["version"]
        installation_id = request["installation_id"]
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
            if decision.authorized:
                self._ensure_module_server()
            return {"authorized": decision.authorized, "reason": decision.reason or decision.state.value}
        except Exception:
            return {"authorized": False, "reason": "unverifiable_signed_lease"}

    def _authorize_bundle_source(self, policy: BundlePolicy,
                                 installation_id: str) -> LaunchAuthorizationDecision:
        """Freshly re-evaluate the signed local Air Stack lease for each module launch."""
        manifest, decision = self._verified_local_authorization(
            policy.source.product_id, policy.source.version, installation_id)
        if manifest is None or decision is None or not decision.authorized:
            return LaunchAuthorizationDecision(
                False, LaunchAuthorizationReason.AUTHORIZATION_DENIED,
                policy.source.product_id,
                installation_id=installation_id,
                device_id=self.device_id,
                product_version=policy.source.version,
            )
        return LaunchAuthorizationDecision(
            True, LaunchAuthorizationReason.AUTHORIZED_OFFLINE,
            policy.source.product_id,
            expires_at=decision.expires_at,
            installation_id=installation_id,
            device_id=self.device_id,
            product_version=policy.source.version,
        )

    def _bundle_policy_candidates(self) -> list[Path]:
        candidates = list(get_bundle_policies_dir().glob("*.json"))
        for record in self.database.list_discovered_products():
            product_policy_dir = Path(record.product_root) / "bundle-policies"
            if product_policy_dir.is_dir():
                candidates.extend(product_policy_dir.glob("*.json"))
        unique: dict[Path, None] = {}
        for candidate in candidates:
            try:
                unique[candidate.resolve()] = None
            except OSError:
                continue
        return sorted(unique)

    def _build_module_server(self) -> ModuleLaunchPipeServer | None:
        """Build Windows IPC only from Agent-verified signed policies and discovery state."""
        if os.name != "nt":
            return None
        keys = _load_trusted_keys(get_trusted_keys_dir())
        if not keys:
            return None
        verifier = SignedBundlePolicyVerifier(keys)
        contexts: dict[str, ModuleLaunchContext] = {}
        for path in self._bundle_policy_candidates():
            try:
                envelope = json.loads(path.read_text())
                policy = verifier.verify(envelope)
                source_resolved = self._validated_product_record(
                    policy.source.product_id, policy.source.version, refresh_on_miss=False)
                target_resolved = self._validated_product_record(
                    policy.target.product_id, policy.target.version, refresh_on_miss=False)
                if source_resolved is None or target_resolved is None:
                    continue
                source_record, source_manifest = source_resolved
                target_record, target_manifest = target_resolved
                if source_manifest.entryPoint.replace("\\", "/") != policy.source.entry_point:
                    continue
                if target_manifest.entryPoint.replace("\\", "/") != policy.target.entry_point:
                    continue
                source_path = Path(source_record.entry_point_path).resolve()
                target_root = Path(target_record.product_root).resolve()
                artifact = ArtifactMetadata(
                    policy.target.product_id,
                    policy.target.version,
                    target_manifest.entryPoint,
                    policy.target.sha256,
                )
                contexts[policy.policy_id] = ModuleLaunchContext(
                    policy, source_path, target_manifest, target_root, artifact)
            except (OSError, ValueError, json.JSONDecodeError, ModuleLaunchDenied):
                continue
        if not contexts:
            return None
        from .execution.windows_ipc import process_identity_from_pid
        service = EnterpriseModuleLaunchService(
            LaunchExecutionService(), process_identity_from_pid)
        dispatcher = EnterpriseModulePipeDispatcher(
            service, contexts, self._authorize_bundle_source)
        return ModuleLaunchPipeServer(dispatcher)

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
            if decision.authorized:
                self._ensure_module_server()
            return {"authorized": decision.authorized, "reason": decision.reason or decision.state.value}
        except Exception:
            return {"authorized": False, "reason": "activation_failed"}

    def open_license_center(self, request: dict[str, str]) -> dict[str, object]:
        product_id = request["product_id"]
        version = request["version"]
        manifest = self._validated_product(product_id, version)
        correlation_id = request.get("correlation_id") or str(uuid.uuid4())
        if manifest is None:
            return {"outcome": "invalid_product_context", "reason": "invalid product context",
                    "correlation_id": correlation_id, "authorization_changed": False}
        typed = OpenLicenseCenterRequest(
            product_id=product_id, product_version=version,
            action=LicenseCenterAction.ACTIVATION_REQUIRED,
            correlation_id=correlation_id, manifest=manifest,
            safe_context={"installation_id": request["installation_id"]},
        )
        result = LicenseCenterService(NativeLicenseCenterLauncher()).open_license_center(typed)
        return result.model_dump()

    def serve_forever(self) -> None:
        if self._module_server is not None:
            self._module_server.start()
        self._update_stop.clear()
        self._update_thread = threading.Thread(target=self._refresh_updates_background, daemon=True, name="bke-update-refresh")
        self._update_thread.start()
        with LocalAuthorizationServer(
            self.authorize, self.activate, self.open_license_center,
            update_status=self.product_update_status,
            refresh_update=self.request_update_refresh,
            dismiss_update=self.dismiss_update,
            open_update_center=self.open_update_center,
            port=self.port,
        ) as server:
            self._server = server
            try:
                while not self._update_stop.wait(1):
                    pass
            except KeyboardInterrupt:
                self._update_stop.set()
                return
            finally:
                self._update_stop.set()
                self._server = None
                if self._module_server is not None:
                    self._module_server.stop()

    def close(self) -> None:
        self._update_stop.set()
        if self._server is not None:
            self._server.close()
            self._server = None
        if self._module_server is not None:
            self._module_server.stop()
        self.database.close()
