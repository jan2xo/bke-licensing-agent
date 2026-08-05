import importlib.util
from pathlib import Path

from bke_licensing_agent.licensing.launch_authorization import AuthorizationDecision, AuthorizationReason


PATH = Path(__file__).parents[1] / "demo_app.py"
SPEC = importlib.util.spec_from_file_location("demo_app", PATH)
demo_app = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(demo_app)


def decision(allowed):
    return AuthorizationDecision(allowed, AuthorizationReason.AUTHORIZED_OFFLINE if allowed else AuthorizationReason.AUTHORIZATION_DENIED, "bke-demo-product")


def test_denied_authorization_exits_without_running(capsys):
    assert demo_app.run(lambda manifest: decision(False)) == 1
    output = capsys.readouterr().out
    assert "DENIED" in output
    assert "Authorization: supplied" not in output
    assert "Status: RUNNING" not in output


def test_authorized_demo_enters_and_cleanly_exits_running_state(monkeypatch, capsys):
    monkeypatch.setattr(demo_app.signal, "pause", lambda: (_ for _ in ()).throw(KeyboardInterrupt))
    assert demo_app.run(lambda manifest: decision(True)) == 0
    output = capsys.readouterr().out
    assert "Authorization: AUTHORIZED" in output
    assert "Status: RUNNING" in output
    assert "shutting down" in output
