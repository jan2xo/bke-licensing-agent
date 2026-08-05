import json
from pathlib import Path

from bke_licensing_agent.manifest.validator import validate_manifest


def test_demo_manifest_is_validated():
    path = Path(__file__).parents[1] / "bke.manifest.json"
    manifest = validate_manifest(json.loads(path.read_text()))
    assert manifest.productId == "bke-demo-product"
    assert manifest.version == "1.0.0"
