"""Agent-owned orchestration boundary for bke-updater-core.

This module contains no product-specific update logic and accepts no remote
commands. Network policy acquisition is deliberately injected by the Agent.
"""
from __future__ import annotations
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from bke_updater_core import PolicyVerifier, decide_update
from bke_updater_core.models import Decision, ProductManifest, SignedUpdatePolicy
from bke_updater_core.paths import validate_manifest_paths
from bke_updater_core.state import TransactionStore

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
    def offline_decision(self, manifest: ProductManifest, cached: dict|None) -> Decision:
        if cached is None: return Decision.UNSUPPORTED
        policy=cached["policy"]
        verified=self.verify_policy(policy,manifest)
        return self.decide(manifest,verified)
