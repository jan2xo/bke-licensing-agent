import base64, hashlib, json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bke_licensing_agent.execution.module_launch import (
    EnterpriseModuleLaunchService, ModuleLaunchDenied, PeerIdentity, SignedBundlePolicyVerifier,
)
from bke_licensing_agent.execution.service import ArtifactMetadata, LaunchExecutionService
from bke_licensing_agent.execution.module_pipe import (
    EnterpriseModulePipeDispatcher, ModuleLaunchContext, ModuleLaunchPipeServer, SCHEMA,
)
from bke_licensing_agent.licensing.launch_authorization import AuthorizationDecision, AuthorizationReason
from bke_licensing_agent.manifest.validator import validate_manifest


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


class Process:
    def __init__(self, pid=77): self.pid, self.dead = pid, False
    def poll(self): return -15 if self.dead else None
    def terminate(self): self.dead = True


def signed_policy(source: Path, target: Path):
    key = Ed25519PrivateKey.generate()
    data = {"schema":"bke.bundle-policy.v1", "policy_id":"air-stack-render-dock-v1",
            "source":{"product_id":"bke-air-stack","version":"1.0.0","entry_point":source.name,"sha256":hashlib.sha256(source.read_bytes()).hexdigest()},
            "target":{"product_id":"bke-render-dock","version":"1.0.0","entry_point":target.name,"sha256":hashlib.sha256(target.read_bytes()).hexdigest()}}
    payload = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    envelope = {"payload":base64.b64encode(payload).decode(),"signature":base64.b64encode(key.sign(payload)).decode(),"key_id":"test","algorithm":"Ed25519"}
    return SignedBundlePolicyVerifier({"test":public}), envelope


def decision(product, installation="installation", device="device"):
    return AuthorizationDecision(True, AuthorizationReason.AUTHORIZED_OFFLINE, product,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1), installation_id=installation, device_id=device, product_version="1.0.0")


def fixture(tmp_path):
    source = tmp_path/"AirStack.exe"; source.write_bytes(b"air")
    root = tmp_path/"render"; root.mkdir(); target=root/"RenderDock.exe"; target.write_bytes(b"dock")
    verifier,envelope=signed_policy(source,target); policy=verifier.verify(envelope)
    manifest=validate_manifest({"schemaVersion":1,"productId":"bke-render-dock","displayName":"Render Dock","version":"1.0.0","entryPoint":"RenderDock.exe","updateChannel":"stable","minimumAgentVersion":"1.0.0","platform":"windows","architecture":"x64"})
    artifact=ArtifactMetadata("bke-render-dock","1.0.0","RenderDock.exe",hashlib.sha256(target.read_bytes()).hexdigest())
    source_peer=PeerIdentity(10,str(source),hashlib.sha256(source.read_bytes()).hexdigest(),1)
    child_peer=PeerIdentity(77,str(target),hashlib.sha256(target.read_bytes()).hexdigest(),2)
    return verifier,envelope,policy,manifest,artifact,root,source_peer,child_peer


def test_signed_policy_rejects_tampering_and_absolute_paths(tmp_path):
    verifier,envelope,*_=fixture(tmp_path)
    verifier.verify(envelope)
    broken=dict(envelope); broken["payload"]=base64.b64encode(b"{}").decode()
    with pytest.raises(ModuleLaunchDenied): verifier.verify(broken)

    key = Ed25519PrivateKey.generate()
    payload = json.dumps({"schema":"bke.bundle-policy.v1","policy_id":"bad","source":{
        "product_id":"bke-air-stack","version":"1.0.0","entry_point":str((tmp_path/"AirStack.exe").resolve()),"sha256":"0"*64},
        "target":{"product_id":"bke-render-dock","version":"1.0.0","entry_point":"RenderDock.exe","sha256":"0"*64}},
        sort_keys=True,separators=(",", ":")).encode()
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    invalid={"payload":base64.b64encode(payload).decode(),"signature":base64.b64encode(key.sign(payload)).decode(),"key_id":"k","algorithm":"Ed25519"}
    with pytest.raises(ModuleLaunchDenied): SignedBundlePolicyVerifier({"k":public}).verify(invalid)


def test_exact_child_single_use_and_offline_decision(tmp_path):
    _,_,policy,manifest,artifact,root,source,child=fixture(tmp_path)
    source_path=Path(source.path)
    process=Process(); execution=LaunchExecutionService(popen=lambda *a,**k:process)
    peers={"source":source,"child":child}
    service=EnterpriseModuleLaunchService(execution, lambda pid: child, lambda handle:peers[handle], clock=lambda:NOW)
    assert service.launch(policy,"source",decision("bke-air-stack"),source_path,manifest,root,artifact)==77
    session=service.redeem("child")
    assert session.pid==77
    with pytest.raises(ModuleLaunchDenied, match="unknown_or_used"): service.redeem("child")


@pytest.mark.parametrize("change", ["source", "child"])
def test_spoofed_source_or_child_binding_denied(tmp_path, change):
    _,_,policy,manifest,artifact,root,source,child=fixture(tmp_path)
    source_path=Path(source.path)
    peers={"source":source,"child":child}
    process=Process(); service=EnterpriseModuleLaunchService(LaunchExecutionService(popen=lambda *a,**k:process),lambda pid:child,lambda handle:peers[handle],clock=lambda:NOW)
    if change=="source":
        peers["source"]=PeerIdentity(source.pid,source.path,"0"*64,source.creation_time)
        with pytest.raises(ModuleLaunchDenied, match="source_identity"): service.launch(policy,"source",decision("bke-air-stack"),source_path,manifest,root,artifact)
        return
    service.launch(policy,"source",decision("bke-air-stack"),source_path,manifest,root,artifact)
    peers["child"]=PeerIdentity(child.pid,child.path,child.sha256,999)
    with pytest.raises(ModuleLaunchDenied, match="child_binding"): service.redeem("child")


def test_expired_session_denied(tmp_path):
    _,_,policy,manifest,artifact,root,source,child=fixture(tmp_path)
    source_path=Path(source.path)
    times=iter([NOW,NOW+timedelta(minutes=1)])
    peers={"source":source,"child":child}
    service=EnterpriseModuleLaunchService(LaunchExecutionService(popen=lambda *a,**k:Process()),lambda pid:child,lambda handle:peers[handle],clock=lambda:next(times),ttl=timedelta(seconds=5))
    service.launch(policy,"source",decision("bke-air-stack"),source_path,manifest,root,artifact)
    with pytest.raises(ModuleLaunchDenied, match="expired"): service.redeem("child")


def test_dispatcher_fresh_authorizes_source_installation_and_redeems_without_echo(tmp_path):
    _,_,policy,manifest,artifact,root,source,child=fixture(tmp_path)
    source_path=Path(source.path)
    peers={"source":source,"child":child}
    service=EnterpriseModuleLaunchService(LaunchExecutionService(popen=lambda *a,**k:Process()),lambda pid:child,lambda handle:peers[handle],clock=lambda:NOW)
    calls=[]
    dispatcher=EnterpriseModulePipeDispatcher(service,{policy.policy_id:ModuleLaunchContext(policy,source_path,manifest,root,artifact)},
        lambda _policy,installation:(calls.append(installation) or decision("bke-air-stack",installation=installation)))
    launched=dispatcher("source",{"operation":"launch","policy_id":policy.policy_id,"installation_id":"air-install"})
    redeemed=dispatcher("child",{"operation":"redeem"})
    assert launched["child_pid"]==77 and calls==["air-install"]
    assert redeemed["enterprise"] is True and redeemed["policy_id"]==policy.policy_id


def test_wire_schema_has_explicit_success_and_denial():
    server=ModuleLaunchPipeServer(lambda _pipe,request:{"operation":request["operation"]})
    assert server._dispatch(object(),{"schema":SCHEMA,"request_id":"r1","operation":"launch"}) == {
        "schema":SCHEMA,"request_id":"r1","ok":True,"result":{"operation":"launch"}}
    denied=server._dispatch(object(),{"schema":"wrong","request_id":"r2","operation":"launch"})
    assert denied=={"schema":SCHEMA,"request_id":"r2","ok":False,"error":"invalid_request"}
