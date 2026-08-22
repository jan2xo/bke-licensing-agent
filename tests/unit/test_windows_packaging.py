from pathlib import Path


ROOT = Path(__file__).parents[2]


def test_windows_service_freeze_includes_and_exercises_pywin32_dependencies():
    service_entry = (ROOT / "packaging/windows/service_entry.py").read_text()
    workflow = (ROOT / ".github/workflows/packaging.yml").read_text()

    assert "import win32timezone" in service_entry
    assert '"--service-smoke" in sys.argv[1:]' in service_entry
    assert "win32serviceutil.GetServiceClassString(LicensingAgentService)" in service_entry
    assert "--hidden-import win32timezone" in workflow
    assert "bke-licensing-agent-service.exe --smoke" in workflow
    assert "bke-licensing-agent-service.exe --service-smoke" in workflow


def test_windows_installer_preserves_service_and_state_contracts():
    service_entry = (ROOT / "packaging/windows/service_entry.py").read_text()
    installer = (ROOT / "packaging/windows/bke-licensing-agent.iss").read_text()

    assert '_svc_name_ = "BKE-Licensing-Agent"' in service_entry
    assert "RunServiceCommand('--startup auto install'" in installer
    assert "RunServiceCommand('start'" in installer
    assert "ewWaitUntilTerminated" in installer
    assert "ResultCode <> 0" in installer
    assert "RaiseException" in installer
    assert 'Parameters: "stop"; RunOnceId: "StopBkeLicensingAgent"' in installer
    assert 'Parameters: "remove"; RunOnceId: "RemoveBkeLicensingAgent"' in installer
    assert 'Type: filesandordirs; Name: "{app}"' in installer
    assert 'Type: filesandordirs; Name: "{#DataDir}"' not in installer
