from datetime import datetime, timezone
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parents[2]))

import pytest

from bke_licensing_agent.licensing.authorization import AuthorizationService
from bke_licensing_agent.manifest.validator import validate_manifest
from bke_licensing_agent.storage.database import Database
from certification.agent import CertificationAgent
from certification.mock_platform import MockBKEPlatform


def demo_manifest():
    return validate_manifest({
        "schemaVersion": 1, "productId": "bke-demo-product",
        "displayName": "BKE Demo Product", "version": "1.0.0",
        "entryPoint": "demo_app.py", "updateChannel": "stable",
        "minimumAgentVersion": "1.0.0", "platform": "linux", "architecture": "x64",
    })


def test_complete_persisted_multi_license_lifecycle(tmp_path):
    manifest = demo_manifest()
    platform = MockBKEPlatform()
    with Database(tmp_path / "certification.db") as database:
        agent = CertificationAgent(platform=platform, database=database, license_key="CERT-LICENSE-A")
        assert agent.licenses.list_for_product(manifest.productId) == []
        assert agent.licenses.active(manifest.productId, agent.installation_id, agent.device_id) is None
        with pytest.raises(RuntimeError, match="activation_required"):
            agent.authorize(manifest)

        agent.activate(manifest)
        assert {item.license_id for item in agent.licenses.list_for_product(manifest.productId)} == {"cert-license-a"}
        assert agent.licenses.active(manifest.productId, agent.installation_id, agent.device_id).active_license_id == "cert-license-a"
        assert agent.authorize(manifest).edition == "Certification A"
        assert agent.authorize(manifest).features == ("cert.feature.a",)
        assert agent.authorize(manifest).limits["cert.projects"] == 1

        agent.login_with_license_key("CERT-LICENSE-B")
        agent.add_license(manifest)
        assert {item.license_id for item in agent.licenses.list_for_product(manifest.productId)} == {"cert-license-a", "cert-license-b"}
        assert agent.licenses.active(manifest.productId, agent.installation_id, agent.device_id).active_license_id == "cert-license-a"
        assert agent.authorize(manifest).edition == "Certification A"

        old_version = agent.licenses.active(manifest.productId, agent.installation_id, agent.device_id).binding_version
        agent.select_license(manifest, "cert-license-b")
        assert agent.licenses.active(manifest.productId, agent.installation_id, agent.device_id).binding_version == old_version + 1
        assert agent.authorize(manifest).edition == "Certification B"
        assert "cert.feature.b" in agent.authorize(manifest).features
        assert agent.authorize(manifest).limits["cert.projects"] == 10

        del agent
        agent = CertificationAgent(platform=MockBKEPlatform(), database=database)
        assert {item.license_id for item in agent.licenses.list_for_product(manifest.productId)} == {"cert-license-a", "cert-license-b"}
        assert agent.licenses.active(manifest.productId, agent.installation_id, agent.device_id).active_license_id == "cert-license-b"
        assert agent.authorize(manifest).edition == "Certification B"

        agent.login_with_license_key("CERT-LICENSE-C")
        agent.add_license(manifest)
        agent.select_license(manifest, "cert-license-c")
        decision = agent.authorize(manifest)
        assert decision.edition == "Certification C"
        assert decision.features == ("cert.feature.a", "cert.feature.b", "cert.feature.c")
        assert decision.limits["cert.projects"] == 100

        agent.login_with_license_key("CERT-LICENSE-BAD-SIGNATURE")
        with pytest.raises(RuntimeError):
            agent.add_license(manifest)
        assert {item.license_id for item in agent.licenses.list_for_product(manifest.productId)} == {
            "cert-license-a", "cert-license-b", "cert-license-c"}
        assert agent.licenses.active(manifest.productId, agent.installation_id, agent.device_id).active_license_id == "cert-license-c"
        assert agent.authorize(manifest).edition == "Certification C"

        with pytest.raises(RuntimeError, match="active_license"):
            agent.remove_license(manifest, "cert-license-c")
        agent.remove_license(manifest, "cert-license-a")
        assert {item.license_id for item in agent.licenses.list_for_product(manifest.productId)} == {
            "cert-license-b", "cert-license-c"}
        assert agent.licenses.active(manifest.productId, agent.installation_id, agent.device_id).active_license_id == "cert-license-c"

        del agent
        agent = CertificationAgent(platform=MockBKEPlatform(), database=database)
        assert agent.licenses.active(manifest.productId, agent.installation_id, agent.device_id).active_license_id == "cert-license-c"
        assert agent.authorize(manifest).edition == "Certification C"
