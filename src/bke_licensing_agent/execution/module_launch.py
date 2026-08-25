"""Signed bundle policy and child-bound enterprise module rendezvous."""

import base64
import hashlib
import json
import threading
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .service import ArtifactMetadata, ExecutionState, LaunchExecutionService
from ..licensing.launch_authorization import AuthorizationDecision
from ..manifest.models import Manifest


class ModuleLaunchDenied(Exception):
    pass


@dataclass(frozen=True)
class BinaryIdentity:
    product_id: str
    version: str
    path: str
    sha256: str


@dataclass(frozen=True)
class BundlePolicy:
    policy_id: str
    source: BinaryIdentity
    target: BinaryIdentity


@dataclass(frozen=True)
class PeerIdentity:
    pid: int
    path: str
    sha256: str
    creation_time: int


@dataclass(frozen=True)
class PendingSession:
    policy_id: str
    pid: int
    creation_time: int
    path: str
    sha256: str
    installation_id: str
    device_id: str
    expires_at: datetime


class SignedBundlePolicyVerifier:
    """Verifies canonical Ed25519 envelopes; writable policy JSON is never trusted alone."""

    def __init__(self, trusted_keys: Mapping[str, str]):
        self._trusted_keys = dict(trusted_keys)

    def verify(self, envelope: Mapping[str, object]) -> BundlePolicy:
        if set(envelope) != {"payload", "signature", "key_id", "algorithm"}:
            raise ModuleLaunchDenied("malformed_policy_envelope")
        if envelope["algorithm"] != "Ed25519" or envelope["key_id"] not in self._trusted_keys:
            raise ModuleLaunchDenied("untrusted_policy_key")
        try:
            payload = base64.b64decode(str(envelope["payload"]), validate=True)
            signature = base64.b64decode(str(envelope["signature"]), validate=True)
            key = serialization.load_pem_public_key(self._trusted_keys[str(envelope["key_id"])].encode())
            if not isinstance(key, Ed25519PublicKey):
                raise ValueError("not Ed25519")
            key.verify(signature, payload)
            data = json.loads(payload)
            if set(data) != {"schema", "policy_id", "source", "target"} or data["schema"] != "bke.bundle-policy.v1":
                raise ValueError("schema")
            return BundlePolicy(str(data["policy_id"]), self._binary(data["source"]), self._binary(data["target"]))
        except Exception as exc:
            if isinstance(exc, ModuleLaunchDenied):
                raise
            raise ModuleLaunchDenied("invalid_policy_signature_or_payload") from exc

    @staticmethod
    def _binary(value: object) -> BinaryIdentity:
        if not isinstance(value, dict) or set(value) != {"product_id", "version", "path", "sha256"}:
            raise ValueError("binary identity")
        digest = str(value["sha256"]).lower()
        path = str(value["path"])
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest) or not Path(path).is_absolute():
            raise ValueError("binary identity")
        return BinaryIdentity(str(value["product_id"]), str(value["version"]), path, digest)


class EnterpriseModuleLaunchService:
    """Authenticates the source peer, launches the target, and binds one redemption to that child."""

    def __init__(self, execution: LaunchExecutionService, process_identity: Callable[[int], PeerIdentity],
                 peer_from_pipe: Callable[[object], PeerIdentity] | None = None,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc), ttl: timedelta = timedelta(seconds=30)):
        self._execution, self._process_identity, self._clock, self._ttl = execution, process_identity, clock, ttl
        if peer_from_pipe is None:
            from .windows_ipc import peer_identity_from_pipe
            peer_from_pipe = peer_identity_from_pipe
        self._peer_from_pipe = peer_from_pipe
        self._lock = threading.Lock()
        self._pending: dict[int, PendingSession] = {}

    @staticmethod
    def _matches(peer: PeerIdentity, binary: BinaryIdentity) -> bool:
        return (Path(peer.path).resolve() == Path(binary.path).resolve() and
                peer.sha256.lower() == binary.sha256.lower())

    def launch(self, policy: BundlePolicy, source_pipe: object,
               source_decision: AuthorizationDecision, target_manifest: Manifest,
               target_root: Path, target_artifact: ArtifactMetadata) -> int:
        source_peer = self._peer_from_pipe(source_pipe)
        if (source_decision.product_id != policy.source.product_id or not source_decision.allowed or
                not self._matches(source_peer, policy.source)):
            raise ModuleLaunchDenied("source_identity_denied")
        if (target_manifest.productId != policy.target.product_id or target_manifest.version != policy.target.version or
                Path(policy.target.path).resolve() != (Path(target_root).resolve() / target_manifest.entryPoint).resolve() or
                target_artifact.sha256.lower() != policy.target.sha256):
            raise ModuleLaunchDenied("target_policy_mismatch")
        target_decision = replace(source_decision, product_id=policy.target.product_id,
                                  product_version=policy.target.version)
        result = self._execution.launch(target_manifest, target_root, target_decision, target_artifact)
        if result.state is not ExecutionState.LAUNCHED or result.pid is None:
            raise ModuleLaunchDenied(f"target_launch_{result.state.value}")
        child = self._process_identity(result.pid)
        if not self._matches(child, policy.target):
            self._execution.terminate(target_manifest.productId)
            raise ModuleLaunchDenied("launched_child_identity_mismatch")
        if not target_decision.installation_id or not target_decision.device_id:
            self._execution.terminate(target_manifest.productId)
            raise ModuleLaunchDenied("target_binding_missing")
        pending = PendingSession(policy.policy_id, child.pid, child.creation_time, child.path, child.sha256,
                                 target_decision.installation_id, target_decision.device_id, self._clock() + self._ttl)
        with self._lock:
            self._pending[child.pid] = pending
        return child.pid

    def redeem(self, target_pipe: object, installation_id: str, device_id: str) -> PendingSession:
        peer = self._peer_from_pipe(target_pipe)
        with self._lock:
            pending = self._pending.pop(peer.pid, None)
        if pending is None:
            raise ModuleLaunchDenied("unknown_or_used_session")
        if self._clock() >= pending.expires_at:
            raise ModuleLaunchDenied("session_expired")
        if (peer.creation_time != pending.creation_time or Path(peer.path).resolve() != Path(pending.path).resolve() or
                peer.sha256.lower() != pending.sha256.lower() or installation_id != pending.installation_id or
                device_id != pending.device_id):
            raise ModuleLaunchDenied("child_binding_mismatch")
        return pending
