"""Signed update preparation; installation is intentionally out of scope."""

import base64
import hashlib
import json
import shutil
import threading
from dataclasses import asdict
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from packaging.version import Version


class UpdateState(StrEnum):
    UPDATE_READY = "update_ready"
    NO_UPDATE = "no_update"
    INCOMPATIBLE = "incompatible"
    VERIFICATION_FAILED = "verification_failed"
    ROLLBACK_REQUIRED = "rollback_required"
    MANUAL_INTERVENTION = "manual_intervention"
    STAGING_FAILED = "staging_failed"


class ResumeMetadataCorruptionError(ValueError):
    """Persisted resume metadata is present but cannot be trusted."""


class RollbackState(StrEnum):
    ROLLBACK_NOT_REQUIRED = "rollback_not_required"
    ROLLBACK_AVAILABLE = "rollback_available"
    ROLLBACK_REQUIRED = "rollback_required"
    ROLLBACK_REJECTED = "rollback_rejected"
    MANUAL_INTERVENTION_REQUIRED = "manual_intervention_required"


class UpdateManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    product_id: str
    version: str
    minimum_agent_version: str
    release_channel: str
    artifact_sha256: str = Field(min_length=64, max_length=64)
    artifact_size: int = Field(ge=0)
    publication_timestamp: datetime
    key_id: str
    signature: str
    artifacts: list[dict[str, Any]] | None = None


@dataclass(frozen=True)
class UpdateDecision:
    state: UpdateState
    version: str | None = None
    reason: str = ""


@dataclass(frozen=True)
class ResumeMetadata:
    product_id: str
    target_version: str
    artifact_id: str
    expected_size: int
    expected_sha256: str
    downloaded_bytes: int
    temporary_path: str
    updated_at: datetime


class UpdateService:
    def __init__(self, trusted_keys: dict[str, str], agent_version: str,
                 channel: str = "stable", copyfile: Any = shutil.copyfile):
        self.trusted_keys = trusted_keys
        self.agent_version = Version(agent_version)
        if channel not in {"stable", "beta", "internal"}:
            raise ValueError("Unsupported update channel")
        self.channel = channel
        self.copyfile = copyfile
        self._condition = threading.Condition()
        self._checks: dict[tuple[str, str], tuple[threading.Event, UpdateDecision | None]] = {}
        self._completed: dict[tuple[str, str], UpdateDecision] = {}

    def check(self, product_id: str, current_version: str, fetch: Any) -> UpdateDecision:
        key = (product_id, self.channel)
        with self._condition:
            entry = self._checks.get(key)
            if entry is None:
                event = threading.Event()
                self._checks[key] = (event, None)
                owner = True
            else:
                event = entry[0]
                owner = False
        if not owner:
            event.wait()
            with self._condition:
                return self._completed.get(key, UpdateDecision(UpdateState.VERIFICATION_FAILED, reason="Missing result"))
        try:
            result = self.evaluate(fetch(), current_version, product_id)
            with self._condition:
                self._checks[key] = (event, result)
                self._completed[key] = result
            return result
        finally:
            with self._condition:
                event.set()
                self._checks.pop(key, None)

    @staticmethod
    def rollback(failed: bool, previous_version: str | None,
                 current_version: str, downgrade_allowed: bool = False) -> RollbackState:
        if not failed:
            return RollbackState.ROLLBACK_NOT_REQUIRED
        if previous_version is None:
            return RollbackState.MANUAL_INTERVENTION_REQUIRED
        if not downgrade_allowed:
            return RollbackState.ROLLBACK_REJECTED
        if Version(previous_version) >= Version(current_version):
            return RollbackState.ROLLBACK_REJECTED
        return RollbackState.ROLLBACK_AVAILABLE

    @staticmethod
    def validate_resume(metadata: ResumeMetadata, now: datetime,
                        product_id: str, target_version: str) -> bool:
        return (metadata.product_id == product_id and metadata.target_version == target_version
                and 0 <= metadata.downloaded_bytes <= metadata.expected_size
                and len(metadata.expected_sha256) == 64
                and metadata.updated_at.tzinfo is not None
                and metadata.updated_at <= now)

    def evaluate(self, raw: dict[str, Any], current_version: str,
                 product_id: str) -> UpdateDecision:
        try:
            data = dict(raw)
            signature = data["signature"]
            key_id = data["key_id"]
            if data.get("signature_algorithm", "Ed25519") != "Ed25519":
                raise ValueError("Unknown signature algorithm")
            if "artifact_sha256" not in data or not isinstance(data["artifact_sha256"], str):
                raise ValueError("Missing artifact metadata")
            manifest = UpdateManifest.model_validate(data)
            if manifest.artifacts is not None:
                if not manifest.artifacts:
                    raise ValueError("Empty artifact list")
                identities = [item.get("artifact_id") for item in manifest.artifacts]
                paths = [item.get("path") for item in manifest.artifacts]
                if None in identities or None in paths or len(set(identities)) != len(identities) or len(set(paths)) != len(paths):
                    raise ValueError("Duplicate or ambiguous artifacts")
            if len(manifest.artifact_sha256) != 64 or any(c not in "0123456789abcdefABCDEF" for c in manifest.artifact_sha256):
                raise ValueError("Invalid hash")
            self._verify(manifest, {k: v for k, v in data.items() if k != "signature"}, signature, key_id)
        except (KeyError, TypeError, ValueError, ValidationError, InvalidSignature):
            return UpdateDecision(UpdateState.VERIFICATION_FAILED, reason="Invalid signed metadata")
        if manifest.product_id != product_id or manifest.release_channel != self.channel:
            return UpdateDecision(UpdateState.INCOMPATIBLE, reason="Product or channel mismatch")
        if self.agent_version < Version(manifest.minimum_agent_version):
            return UpdateDecision(UpdateState.INCOMPATIBLE, reason="Agent version is unsupported")
        if Version(manifest.version) <= Version(current_version):
            return UpdateDecision(UpdateState.NO_UPDATE, manifest.version, "No newer version")
        if manifest.publication_timestamp.tzinfo is None:
            return UpdateDecision(UpdateState.VERIFICATION_FAILED, reason="Timestamp is not timezone-aware")
        return UpdateDecision(UpdateState.UPDATE_READY, manifest.version)

    def verify_artifact(self, path: Path, manifest: UpdateManifest) -> UpdateDecision:
        try:
            if path.stat().st_size != manifest.artifact_size:
                return UpdateDecision(UpdateState.VERIFICATION_FAILED, reason="Artifact size mismatch")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            return UpdateDecision(UpdateState.VERIFICATION_FAILED, reason=str(exc))
        if digest.lower() != manifest.artifact_sha256.lower():
            return UpdateDecision(UpdateState.VERIFICATION_FAILED, reason="Artifact hash mismatch")
        return UpdateDecision(UpdateState.UPDATE_READY, manifest.version)

    def stage(self, source: Path, staging_dir: Path, manifest: UpdateManifest) -> UpdateDecision:
        target = staging_dir / "artifact.part"
        try:
            staging_dir.mkdir(parents=True, exist_ok=True)
            if target.exists():
                return UpdateDecision(UpdateState.STAGING_FAILED, reason="Staging destination already exists")
            source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
            if source_digest.lower() != manifest.artifact_sha256.lower():
                return UpdateDecision(UpdateState.VERIFICATION_FAILED, reason="Source changed before staging")
            self.copyfile(source, target)
            if hashlib.sha256(source.read_bytes()).hexdigest().lower() != source_digest.lower():
                target.unlink(missing_ok=True)
                return UpdateDecision(UpdateState.VERIFICATION_FAILED, reason="Source changed during staging")
            decision = self.verify_artifact(target, manifest)
            if decision.state is not UpdateState.UPDATE_READY:
                target.unlink(missing_ok=True)
            return decision
        except (OSError, ValueError) as exc:
            try:
                target.unlink(missing_ok=True)
            except OSError:
                pass
            return UpdateDecision(UpdateState.STAGING_FAILED, reason=str(exc))

    @staticmethod
    def cleanup(staging_dir: Path) -> None:
        shutil.rmtree(staging_dir, ignore_errors=True)

    def _verify(self, manifest: UpdateManifest, raw: dict[str, Any], signature: str, key_id: str) -> None:
        pem = self.trusted_keys.get(key_id)
        if pem is None:
            raise ValueError("Unknown signing key")
        key = serialization.load_pem_public_key(pem.encode())
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("Unsupported signing key")
        payload = json.dumps({k: v for k, v in raw.items() if k != "signature"},
                             sort_keys=True, separators=(",", ":"), default=str).encode()
        key.verify(base64.b64decode(signature, validate=True), payload)


class ResumeRepository:
    """Durable, non-sensitive resume metadata; contents remain untrusted."""
    def __init__(self, path: Path):
        self.path = path

    def save(self, metadata: ResumeMetadata) -> None:
        self.path.write_text(json.dumps(asdict(metadata), default=str, sort_keys=True))

    def load(self) -> ResumeMetadata | None:
        if not self.path.exists():
            return None
        try:
            data = json.loads(self.path.read_text())
            required = {"product_id", "target_version", "artifact_id", "expected_size",
                        "expected_sha256", "downloaded_bytes", "temporary_path", "updated_at"}
            if not isinstance(data, dict) or set(data) != required:
                raise ValueError("Missing or unknown resume fields")
            metadata = ResumeMetadata(
                data["product_id"], data["target_version"], data["artifact_id"],
                int(data["expected_size"]), data["expected_sha256"],
                int(data["downloaded_bytes"]), data["temporary_path"],
                datetime.fromisoformat(data["updated_at"]),
            )
            if (not metadata.product_id or not metadata.target_version
                    or not metadata.artifact_id or metadata.expected_size < 0
                    or metadata.downloaded_bytes < 0
                    or metadata.downloaded_bytes > metadata.expected_size
                    or len(metadata.expected_sha256) != 64
                    or any(c not in "0123456789abcdefABCDEF" for c in metadata.expected_sha256)
                    or metadata.updated_at.tzinfo is None
                    or not Path(metadata.temporary_path).is_absolute()
                    or ".." in Path(metadata.temporary_path).parts):
                raise ValueError("Invalid resume metadata")
            return metadata
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise ResumeMetadataCorruptionError("Resume metadata is corrupted") from exc

    def clear(self) -> None:
        self.path.unlink(missing_ok=True)
