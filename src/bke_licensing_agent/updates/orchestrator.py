"""Agent-owned orchestration boundary for bke-updater-core.

This module contains no product-specific update logic and accepts no remote
commands. Network acquisition is bounded and verified before core replacement.
"""
from __future__ import annotations
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from bke_updater_core import PolicyVerifier, decide_update, replace_transaction
from bke_updater_core.models import Decision, ProductManifest, SignedUpdatePolicy, UpdatePlan, TransactionState
from bke_updater_core.paths import validate_manifest_paths
from bke_updater_core.state import TransactionStore
from .acquisition import acquire_artifact

@dataclass(frozen=True)
class CachedPolicy:
    policy: dict
    verified_at: str

class UpdateOrchestrator:
    def __init__(self, trusted_keys: dict[str, bytes], state_root: Path):
        self.verifier=PolicyVerifier(trusted_keys)
        self.state=TransactionStore(state_root)
    def validate_product(self, manifest: ProductManifest):
        return validate_manifest_paths(manifest.install_root, manifest.executable)
    def verify_policy(self, policy: dict, manifest: ProductManifest, last_revision: int|None=None) -> SignedUpdatePolicy:
        return self.verifier.verify(policy, product_id=manifest.product_id, platform=manifest.platform,
            architecture=manifest.architecture, channel=manifest.update_channel, last_revision=last_revision)
    def decide(self, manifest: ProductManifest, policy: SignedUpdatePolicy) -> Decision:
        return decide_update(manifest.version, policy.latest_version, policy.minimum_supported_version)
    def cache_verified(self, path: Path, policy: SignedUpdatePolicy, verified_at: str) -> None:
        path.parent.mkdir(parents=True,exist_ok=True)
        tmp=path.with_suffix(path.suffix+".tmp")
        tmp.write_text(json.dumps({"policy":policy.raw,"verified_at":verified_at},sort_keys=True))
        tmp.replace(path)
    def load_cached(self, path: Path) -> dict|None:
        if not path.exists(): return None
        document=json.loads(path.read_text())
        if not isinstance(document,dict) or set(document)!={"policy","verified_at"}: raise ValueError("invalid cached policy envelope")
        return document
    def execute_update(
        self,
        manifest: ProductManifest,
        policy: SignedUpdatePolicy,
        artifact: Path|None,
        backup_root: Path,
        acquire: Callable[[str,int,str],Path]|None=None,
        health_probe=None,
        download_url: str|None=None,
        download_destination: Path|None=None,
    ) -> TransactionState:
        decision = self.decide(manifest, policy)
        if decision not in {Decision.UPDATE_AVAILABLE, Decision.UPDATE_REQUIRED}:
            return TransactionState.FAILED
        staged = artifact
        if acquire is not None:
            staged = acquire(policy.artifact_id, policy.artifact_size, policy.artifact_sha256)
        elif staged is None and download_url is not None and download_destination is not None:
            staged = acquire_artifact(
                download_url, download_destination,
                expected_size=policy.artifact_size,
                expected_sha256=policy.artifact_sha256,
            )
        if staged is None:
            raise ValueError("verified update requires an artifact or bounded acquisition")
        self.validate_product(manifest)
        plan = UpdatePlan(
            manifest.product_id, manifest.install_root, manifest.version,
            policy.latest_version, Path(staged), backup_root,
            manifest.install_root / manifest.executable,
            health_check=manifest.health_check,
            expected_sha256=policy.artifact_sha256,
            expected_size=policy.artifact_size,
        )
        return replace_transaction(plan, health_probe=health_probe)

    def offline_decision(self, manifest: ProductManifest, cached: dict|None) -> Decision:
        if cached is None: return Decision.UNSUPPORTED
        policy=cached["policy"]
        verified=self.verify_policy(policy,manifest)
        return self.decide(manifest,verified)
