from pathlib import Path
import json
import pytest
from bke_licensing_agent.updates.orchestrator import UpdateOrchestrator

def test_cached_policy_tampering_is_rejected(tmp_path):
    orchestrator=UpdateOrchestrator({}, tmp_path/"state")
    path=tmp_path/"cache.json"
    path.write_text(json.dumps({"unexpected":"value"}))
    with pytest.raises(ValueError):
        orchestrator.load_cached(path)

def test_missing_cached_policy_is_not_authorized(tmp_path):
    orchestrator=UpdateOrchestrator({}, tmp_path/"state")
    from bke_updater_core.models import ProductManifest
    manifest=ProductManifest("fixture","1.0.0","linux","x86_64","run",tmp_path)
    assert orchestrator.offline_decision(manifest,None).value=="UNSUPPORTED"
