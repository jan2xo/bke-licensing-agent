"""Agent-owned orchestration boundary for bke-updater-core."""
from __future__ import annotations
import json, re
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
        self.verifier=PolicyVerifier(trusted_keys); self.state=TransactionStore(state_root)
        self._revision_path=state_root / "highest-policy-revision.json"
    def validate_product(self, manifest: ProductManifest): return validate_manifest_paths(manifest.install_root, manifest.executable)
    def _highest_revision(self) -> int|None:
        if not self._revision_path.exists(): return None
        value=json.loads(self._revision_path.read_text()).get("revision")
        return value if isinstance(value,int) else None
    def _accept_revision(self, revision:int) -> None:
        current=self._highest_revision()
        if current is not None and revision < current: raise ValueError("policy revision rollback")
        self._revision_path.parent.mkdir(parents=True,exist_ok=True); self._revision_path.write_text(json.dumps({"revision":revision},sort_keys=True))
    def verify_policy(self, policy: dict, manifest: ProductManifest, last_revision: int|None=None) -> SignedUpdatePolicy:
        return self.verifier.verify(policy,product_id=manifest.product_id,platform=manifest.platform,architecture=manifest.architecture,channel=manifest.update_channel,last_revision=self._highest_revision() if last_revision is None else last_revision)
    def decide(self, manifest: ProductManifest, policy: SignedUpdatePolicy) -> Decision: return decide_update(manifest.version,policy.latest_version,policy.minimum_supported_version)
    def cache_verified(self,path:Path,policy:SignedUpdatePolicy,verified_at:str)->None:
        self._accept_revision(policy.revision); path.parent.mkdir(parents=True,exist_ok=True); tmp=path.with_suffix(path.suffix+".tmp")
        tmp.write_text(json.dumps({"policy":policy.raw,"verified_at":verified_at},sort_keys=True)); tmp.replace(path)
    def load_cached(self,path:Path)->dict|None:
        if not path.exists(): return None
        document=json.loads(path.read_text())
        if not isinstance(document,dict) or set(document)!={"policy","verified_at"}: raise ValueError("invalid cached policy envelope")
        return document
    def _transaction_id(self,manifest:ProductManifest,policy:SignedUpdatePolicy)->str: return re.sub(r"[^A-Za-z0-9_.-]","-",f"{manifest.product_id}-{policy.release_id}-{policy.revision}")[:160]
    def _record(self,transaction_id:str,state:TransactionState,**payload)->None: self.state.write(transaction_id,state,payload)
    def read_transaction(self,transaction_id:str)->dict: return self.state.read(transaction_id)
    def pending_transactions(self)->list[dict]:
        if not self.state.root.exists(): return []
        return [self.state.read(item.name) for item in self.state.root.iterdir() if item.is_dir() and (item/"state.json").exists() and self.state.read(item.name)["state"] not in {x.value for x in (TransactionState.COMMITTED,TransactionState.ROLLED_BACK,TransactionState.FAILED)}]
    def execute_update(self,manifest:ProductManifest,policy:SignedUpdatePolicy,artifact:Path|None,backup_root:Path,acquire:Callable[[str,int,str],Path]|None=None,health_probe=None,download_url:str|None=None,download_destination:Path|None=None,allow_loopback_http:bool=False)->TransactionState:
        decision=self.decide(manifest,policy)
        if decision not in {Decision.UPDATE_AVAILABLE,Decision.UPDATE_REQUIRED}: return TransactionState.FAILED
        transaction_id=self._transaction_id(manifest,policy); self._record(transaction_id,TransactionState.CREATED,product_id=manifest.product_id,target_version=policy.latest_version)
        staged=artifact
        try:
            if acquire is not None: self._record(transaction_id,TransactionState.DOWNLOADING,artifact_id=policy.artifact_id); staged=acquire(policy.artifact_id,policy.artifact_size,policy.artifact_sha256)
            elif staged is None and download_url is not None and download_destination is not None:
                self._record(transaction_id,TransactionState.DOWNLOADING,artifact_id=policy.artifact_id)
                staged=acquire_artifact(download_url,download_destination,expected_size=policy.artifact_size,expected_sha256=policy.artifact_sha256,allow_loopback_http=allow_loopback_http)
        except Exception as exc:
            self._record(transaction_id,TransactionState.FAILED,error=str(exc)); raise
        if staged is None: self._record(transaction_id,TransactionState.FAILED,error="missing verified artifact"); raise ValueError("verified update requires an artifact or bounded acquisition")
        self.validate_product(manifest); self._record(transaction_id,TransactionState.VERIFIED,artifact=str(staged),artifact_id=policy.artifact_id)
        plan=UpdatePlan(manifest.product_id,manifest.install_root,manifest.version,policy.latest_version,Path(staged),backup_root,manifest.install_root/manifest.executable,health_check=manifest.health_check,expected_sha256=policy.artifact_sha256,expected_size=policy.artifact_size)
        result=replace_transaction(plan,health_probe=health_probe); self._record(transaction_id,result,artifact=str(staged),target_version=policy.latest_version); return result
    def execute_self_update(self,manifest:ProductManifest,policy:SignedUpdatePolicy,artifact:Path|None,backup_root:Path,**kwargs)->TransactionState: return self.execute_update(manifest,policy,artifact,backup_root,**kwargs)
    def offline_decision(self,manifest:ProductManifest,cached:dict|None)->Decision:
        if cached is None: return Decision.UNSUPPORTED
        current=self._highest_revision()
        verified=self.verify_policy(cached["policy"],manifest,last_revision=(current-1 if current is not None else None))
        self._accept_revision(verified.revision)
        return self.decide(manifest,verified)
