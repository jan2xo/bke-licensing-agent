import importlib.util
import json
from pathlib import Path

from bke_licensing_agent.licensing.launch_authorization import AuthorizationDecision, AuthorizationReason


PATH = Path(__file__).parents[1] / "demo_app.py"
SPEC = importlib.util.spec_from_file_location("demo_app", PATH)
demo_app = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(demo_app)


def decision(allowed):
    return AuthorizationDecision(allowed, AuthorizationReason.AUTHORIZED_OFFLINE if allowed else AuthorizationReason.AUTHORIZATION_DENIED, "bke-demo-product")


class Agent:
    def __init__(self, allowed): self.allowed = allowed; self.activated = False
    def authorize(self, manifest):
        if not self.activated and self.allowed == "activation_required": raise RuntimeError("activation_required")
        return decision(self.allowed is True or self.activated)


class Center:
    def __init__(self, agent): self.agent = agent; self.screen = None
    def connect(self): pass
    def sign_in(self, key): self.key = key
    def select_product(self, product): pass
    def activate(self):
        self.agent.activated = self.key == "BKE-DEMO-VALID"
        self.screen = type("Screen", (), {"value": "status" if self.agent.activated else "error"})()
        return type("State", (), {"screen": self.screen, "error": "denied"})()


def test_denied_authorization_exits_without_running(capsys):
    assert demo_app.run(Agent(False)) == 1
    output = capsys.readouterr().out
    assert "DENIED" in output
    assert "Authorization: supplied" not in output
    assert "Status: RUNNING" not in output


def test_authorized_demo_enters_and_cleanly_exits_running_state(monkeypatch, capsys):
    monkeypatch.setattr(demo_app.signal, "pause", lambda: (_ for _ in ()).throw(KeyboardInterrupt))
    assert demo_app.run(Agent(True)) == 0
    output = capsys.readouterr().out
    assert "Authorization: AUTHORIZED" in output
    assert "Status: RUNNING" in output
    assert "shutting down" in output


def test_activation_required_opens_center_then_retries(monkeypatch, capsys):
    monkeypatch.setattr(demo_app.signal, "pause", lambda: (_ for _ in ()).throw(KeyboardInterrupt))
    agent = Agent("activation_required")
    assert demo_app.run(agent, Center(agent), "BKE-DEMO-VALID") == 0
    assert "Status: RUNNING" in capsys.readouterr().out


def test_invalid_activation_does_not_enter_running(capsys):
    agent = Agent("activation_required")
    assert demo_app.run(agent, Center(agent), "BKE-DEMO-INVALID") == 1
    assert "RUNNING" not in capsys.readouterr().out


def test_default_wiring_constructs_agent_and_center(monkeypatch):
    agent = Agent("activation_required")
    center = Center(agent)
    monkeypatch.setattr(demo_app, "create_certification_agent", lambda: agent)
    monkeypatch.setattr(demo_app, "create_license_center", lambda supplied: center)
    center.screen = type("Screen", (), {"value": "status"})()
    def launch(_center, _manifest):
        agent.activated = True
        return type("State", (), {"screen": center.screen, "error": None})()
    monkeypatch.setattr(demo_app, "launch_license_center", launch)
    monkeypatch.setattr(demo_app.signal, "pause", lambda: (_ for _ in ()).throw(KeyboardInterrupt))
    assert demo_app.run() == 0


def test_certification_metadata_is_reused_after_reconstruction(tmp_path):
    from certification.agent import CertificationAgent
    from certification.mock_platform import MockBKEPlatform
    from bke_licensing_agent.storage.database import Database

    with Database(tmp_path / "agent.db") as database:
        first = CertificationAgent(platform=MockBKEPlatform(), license_key="BKE-DEMO-VALID", database=database)
        manifest = demo_app.validate_manifest(json.loads((Path(__file__).parents[1] / "bke.manifest.json").read_text()))
        first.activate(manifest)
        second = CertificationAgent(platform=MockBKEPlatform(), database=database)
        assert second.authorize(manifest).authorized
