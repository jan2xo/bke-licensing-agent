from pathlib import Path


SERVICE_ENTRY = Path("packaging/windows/service_entry.py")


def test_frozen_windows_service_uses_scm_host_path_for_no_args() -> None:
    source = SERVICE_ENTRY.read_text(encoding="utf-8")

    assert "elif len(sys.argv) == 1:" in source
    assert "servicemanager.Initialize()" in source
    assert "servicemanager.PrepareToHostSingle(LicensingAgentService)" in source
    assert "servicemanager.StartServiceCtrlDispatcher()" in source
    assert "win32serviceutil.HandleCommandLine(LicensingAgentService)" in source


def test_frozen_windows_service_exposes_host_smoke() -> None:
    source = SERVICE_ENTRY.read_text(encoding="utf-8")

    assert '"--service-host-smoke"' in source
    assert "SCM host functions OK" in source
