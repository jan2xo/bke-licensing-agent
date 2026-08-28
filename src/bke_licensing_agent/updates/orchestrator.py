"""Agent-owned orchestration boundary for bke-updater-core."""
from __future__ import annotations
import json, re, os, shutil, stat, zipfile
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Callable
from bke_updater_core import PolicyVerifier, decide_update, replace_transaction
from bke_updater_core.models import Decision, ProductManifest, SignedUpdatePolicy, UpdatePlan, TransactionState
from bke_updater_core.paths import validate_manifest_paths
from bke_updater_core.state import TransactionStore
from .acquisition import acquire_artifact
from .privileged_runtime import (
    AgentPrivilegedRuntimeConfig,
    invoke_privileged_self_update,
    prepare_privileged_self_update,
    prepare_privileged_update,
)

UPDATE_PACKAGE_CONTENT_TYPE = "application/vnd.bke.update-package+zip"


@dataclass(frozen=True)
class CachedPolicy:
    policy: dict
    verified_at: str


def _prepare_stage_root(stage_root: Path) -> None:
    if stage_root.is_symlink():
        raise ValueError("privileged stage root must not be a symlink")
    if stage_root.exists():
        shutil.rmtree(stage_root)
    stage_root.mkdir(parents=True, exist_ok=False)


def _safe_update_package_member(info: zipfile.ZipInfo) -> tuple[str, ...]:
    name = info.filename
    if not name or "\x00" in name or "\\" in name or name.startswith("/"):
        raise ValueError("unsafe updater package path")
    trimmed = name[:-1] if name.endswith("/") else name
    if not trimmed:
        raise ValueError("unsafe updater package path")
    raw_parts = trimmed.split("/")
    if any(part in {"", ".", ".."} for part in raw_parts):
        raise ValueError("unsafe updater package path")
    pure = PurePosixPath(trimmed)
    if pure.is_absolute() or any(part == ".." for part in pure.parts) or ":" in raw_parts[0]:
        raise ValueError("unsafe updater package path")
    mode = (info.external_attr >> 16) & 0xFFFF
    if stat.S_ISLNK(mode):
        raise ValueError("updater package symlinks are forbidden")
    file_type = stat.S_IFMT(mode)
    if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
        raise ValueError("unsupported updater package entry type")
    return tuple(raw_parts)


def _extract_update_package(artifact: Path, stage_root: Path, relative_entry: Path) -> Path:
    _prepare_stage_root(stage_root)
    stage = stage_root.resolve()
    seen: set[str] = set()
    try:
        with zipfile.ZipFile(artifact, "r") as archive:
            for info in archive.infolist():
                parts = _safe_update_package_member(info)
                collision_key = "/".join(part.casefold() for part in parts)
                if collision_key in seen:
                    raise ValueError("duplicate updater package path")
                seen.add(collision_key)
                destination = (stage / Path(*parts)).resolve()
                try:
                    if os.path.commonpath((str(stage), str(destination))) != str(stage):
                        raise ValueError("unsafe updater package path")
                except ValueError as exc:
                    raise ValueError("unsafe updater package path") from exc
                if info.is_dir():
                    destination.mkdir(parents=True, exist_ok=False)
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info, "r") as source, destination.open("xb") as output:
                    shutil.copyfileobj(source, output)
                mode = (info.external_attr >> 16) & 0o777
                if mode and os.name != "nt":
                    os.chmod(destination, mode)
    except (zipfile.BadZipFile, RuntimeError) as exc:
        raise ValueError("invalid updater package ZIP") from exc

    staged_executable = (stage / relative_entry).resolve()
    try:
        if os.path.commonpath((str(stage), str(staged_executable))) != str(stage):
            raise ValueError("staged entry point escapes stage root")
    except ValueError as exc:
        raise ValueError("staged entry point escapes stage root") from exc
    if not staged_executable.exists() or not staged_executable.is_file():
        raise ValueError("updater package is missing signed entry point")
    return staged_executable


class UpdateOrchestrator:
    def __init__(self, trusted_keys: dict[str, bytes], state_root: Path):
        self.verifier=PolicyVerifier(trusted_keys); self.state=TransactionStore(state_root)
        self._revision_root=state_root / "policy-revisions"
    def validate_product(self, manifest: ProductManifest): return validate_manifest_paths(manifest.install_root, manifest.executable)
    @staticmethod
    def _scope(manifest: ProductManifest) -> str:
        return re.sub(r"[^A-Za-z0-9_.-]", "-", f"{manifest.product_id}-{manifest.platform}-{manifest.architecture}-{manifest.update_channel}")[:180]
    def _revision_path(self, manifest: ProductManifest) -> Path:
        return self._revision_root / f"{self._scope(manifest)}.json"
    def _highest_revision(self, manifest: ProductManifest) -> int|None:
        path=self._revision_path(manifest)
        if not path.exists(): return None
        value=json.loads(path.read_text()).get("revision")
        return value if isinstance(value,int) else None
    def _accept_revision(self, manifest: ProductManifest, revision:int) -> None:
        path=self._revision_path(manifest); current=self._highest_revision(manifest)
        if current is not None and revision < current: raise ValueError("policy revision rollback")
        path.parent.mkdir(parents=True,exist_ok=True); tmp=path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"revision":revision},sort_keys=True)); tmp.replace(path)
    def verify_policy(self, policy: dict, manifest: ProductManifest, last_revision: int|None=None) -> SignedUpdatePolicy:
        return self.verifier.verify(policy,product_id=manifest.product_id,platform=manifest.platform,architecture=manifest.architecture,channel=manifest.update_channel,last_revision=self._highest_revision(manifest) if last_revision is None else last_revision)
    def decide(self, manifest: ProductManifest, policy: SignedUpdatePolicy) -> Decision: return decide_update(manifest.version,policy.latest_version,policy.minimum_supported_version)
    def cache_verified(self,path:Path,policy:SignedUpdatePolicy,verified_at:str,manifest:ProductManifest|None=None)->None:
        if manifest is None: raise ValueError("manifest is required for scoped policy cache")
        self._accept_revision(manifest,policy.revision); path.parent.mkdir(parents=True,exist_ok=True); tmp=path.with_suffix(path.suffix+".tmp")
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

    def _prepare_privileged_handoff(
        self,
        manifest: ProductManifest,
        policy: SignedUpdatePolicy,
        artifact: Path,
        privileged_config: AgentPrivilegedRuntimeConfig,
        target_policy: dict[str, object],
        *,
        wait_pid: int | None,
    ):
        self.validate_product(manifest)
        if policy.product_id != manifest.product_id or policy.current_version != manifest.version:
            raise ValueError("signed update policy does not match installed product")
        if policy.platform != manifest.platform or policy.architecture != manifest.architecture or policy.channel != manifest.update_channel:
            raise ValueError("signed update policy does not match installed product context")
        transaction_id=self._transaction_id(manifest,policy)
        runtime_root=privileged_config.runtime_root.resolve()
        stage_root=runtime_root/"stage"/transaction_id
        entry_value=target_policy.get("entry_point")
        if not isinstance(entry_value,str) or not entry_value:
            raise ValueError("signed target policy is missing entry_point")
        relative=Path(*PureWindowsPath(entry_value).parts)
        if relative.is_absolute() or relative == Path(".") or ".." in relative.parts:
            raise ValueError("signed target policy has invalid entry_point")
        if policy.content_type == UPDATE_PACKAGE_CONTENT_TYPE:
            staged_executable = _extract_update_package(artifact, stage_root, relative)
        else:
            _prepare_stage_root(stage_root)
            staged_executable=stage_root/relative
            staged_executable.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(artifact,staged_executable)
            if os.name != "nt": os.chmod(staged_executable,0o755)
        privileged_backup=runtime_root/"backup"/transaction_id
        privileged_backup.parent.mkdir(parents=True,exist_ok=True)
        prepare = prepare_privileged_self_update if wait_pid is not None else prepare_privileged_update
        kwargs = dict(
            update_policy=policy.raw,
            target_policy=target_policy,
            artifact=artifact,
            staged_root=stage_root,
            backup_root=privileged_backup,
            transaction_id=transaction_id,
        )
        if wait_pid is not None:
            kwargs["wait_pid"] = wait_pid
        prepared=prepare(privileged_config,**kwargs)
        command=list(prepared.command)
        if manifest.health_check:
            command.extend(("--ready-marker",manifest.health_check))
        return transaction_id, replace(prepared,command=tuple(command))

    def execute_privileged_update(
        self,
        manifest: ProductManifest,
        policy: SignedUpdatePolicy,
        artifact: Path | None,
        *,
        privileged_config: AgentPrivilegedRuntimeConfig | None = None,
        target_policy: dict[str, object] | None = None,
        elevate=None,
    )->TransactionState:
        """Hand a normal product update to the signed elevated helper without exiting the Agent."""
        if artifact is None: raise ValueError("privileged update requires a verified artifact")
        if privileged_config is None or target_policy is None:
            raise ValueError("privileged update requires runtime config and signed target policy")
        decision=self.decide(manifest,policy)
        if decision not in {Decision.UPDATE_AVAILABLE,Decision.UPDATE_REQUIRED}: return TransactionState.FAILED
        transaction_id=self._transaction_id(manifest,policy)
        self._record(transaction_id,TransactionState.CREATED,product_id=manifest.product_id,target_version=policy.latest_version,privileged=True)
        transaction_id, prepared=self._prepare_privileged_handoff(
            manifest,policy,artifact,privileged_config,target_policy,wait_pid=None
        )
        self._record(transaction_id,TransactionState.VERIFIED,artifact=str(prepared.artifact_path),privileged=True)
        if elevate is None:
            invoke_privileged_self_update(prepared)
        else:
            invoke_privileged_self_update(prepared,elevate=elevate)
        self._record(transaction_id,TransactionState.STAGED,privileged=True,helper=str(privileged_config.helper_executable),ready_marker=manifest.health_check)
        return TransactionState.STAGED

    def execute_self_update(
        self,
        manifest: ProductManifest,
        policy: SignedUpdatePolicy,
        artifact: Path | None,
        backup_root: Path,
        *,
        privileged_config: AgentPrivilegedRuntimeConfig | None = None,
        target_policy: dict[str, object] | None = None,
        elevate=None,
        exit_process=os._exit,
    )->TransactionState:
        """Compose and hand self-replacement to the signed privileged updater boundary."""
        if artifact is None: raise ValueError("self-update requires a verified artifact")
        if privileged_config is None or target_policy is None:
            raise ValueError("self-update requires privileged runtime config and signed target policy")
        decision=self.decide(manifest,policy)
        if decision not in {Decision.UPDATE_AVAILABLE,Decision.UPDATE_REQUIRED}: return TransactionState.FAILED
        transaction_id=self._transaction_id(manifest,policy)
        self._record(transaction_id,TransactionState.CREATED,product_id=manifest.product_id,target_version=policy.latest_version,self_update=True)
        transaction_id, prepared=self._prepare_privileged_handoff(
            manifest,policy,artifact,privileged_config,target_policy,wait_pid=os.getpid()
        )
        self._record(transaction_id,TransactionState.VERIFIED,artifact=str(prepared.artifact_path),self_update=True)
        if elevate is None:
            invoke_privileged_self_update(prepared)
        else:
            invoke_privileged_self_update(prepared,elevate=elevate)
        self._record(transaction_id,TransactionState.WAITING_FOR_EXIT,self_update=True,helper=str(privileged_config.helper_executable),ready_marker=manifest.health_check)
        exit_process(0)
        return TransactionState.WAITING_FOR_EXIT
    def offline_decision(self,manifest:ProductManifest,cached:dict|None)->Decision:
        if cached is None: return Decision.UNSUPPORTED
        current=self._highest_revision(manifest)
        verified=self.verify_policy(cached["policy"],manifest,last_revision=(current-1 if current is not None else None))
        self._accept_revision(manifest,verified.revision)
        return self.decide(manifest,verified)
