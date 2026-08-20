import hashlib
import shutil
import subprocess
from pathlib import Path
from bke_updater_core.models import ProductManifest, SignedUpdatePolicy, TransactionState
from bke_licensing_agent.updates.orchestrator import UpdateOrchestrator

def make_policy(product, artifact, latest="2.0.0", minimum="1.0.0"):
    return SignedUpdatePolicy("bke.update-policy.v1",product,"1.0.0",latest,minimum,"stable","linux","x86_64","release-2","artifact-2",hashlib.sha256(artifact.read_bytes()).hexdigest(),artifact.stat().st_size,"application/octet-stream","2026-01-01T00:00:00Z","2026-01-01T00:00:00Z",2,"ci","Ed25519","",{})

def run_fixture(tmp_path, fixture_root, broken=False):
    install=tmp_path/"install"; install.mkdir()
    current=fixture_root/"v1"/("product.py" if fixture_root.name=="python" else "product.sh")
    candidate=fixture_root/("broken" if broken else "v2")/current.name
    shutil.copy2(current, install/current.name)
    shutil.copy2(candidate, tmp_path/"candidate")
    for path in (install/current.name, tmp_path/"candidate"):
        path.chmod(0o755)
    manifest=ProductManifest(f"fixture-{fixture_root.name}","1.0.0","linux","x86_64",current.name,install)
    policy=make_policy(manifest.product_id,tmp_path/"candidate")
    def health(path):
        return subprocess.run([str(path),"--health"],capture_output=True).returncode==0
    result=UpdateOrchestrator({},tmp_path/"state").execute_update(manifest,policy,tmp_path/"candidate",tmp_path/"backup",health_probe=health)
    return result, subprocess.run([str(install/current.name)],capture_output=True,text=True).stdout.strip()

def test_python_product_v1_to_v2(tmp_path):
    root=Path("certification/fixtures/python")
    result, output=run_fixture(tmp_path,root)
    assert result is TransactionState.COMMITTED and output=="python-product-v2"

def test_compiled_style_product_v1_to_v2(tmp_path):
    root=Path("certification/fixtures/compiled")
    result, output=run_fixture(tmp_path,root)
    assert result is TransactionState.COMMITTED and output=="compiled-product-v2"

def test_broken_product_rolls_back_to_v1(tmp_path):
    root=Path("certification/fixtures/python")
    result, output=run_fixture(tmp_path,root,broken=True)
    assert result is TransactionState.ROLLED_BACK and output=="python-product-v1"
