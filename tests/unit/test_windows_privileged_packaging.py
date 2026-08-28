from pathlib import Path


def test_windows_installer_owns_privileged_runtime_inputs():
    source = (Path(__file__).parents[2] / "packaging" / "windows" / "bke-licensing-agent.iss").read_text(encoding="utf-8")
    assert "PrivilegesRequired=admin" in source
    assert "bke-updater-core.exe" in source
    assert "bke-privileged-provisioner.exe" in source
    assert "privileged-payload\\target-keys" in source
    assert "privileged-payload\\target-policies" in source
    assert "ProvisionPrivilegedRuntime" in source
    # The installer/runtime contract must not reintroduce the retired generic
    # caller-controlled helper flags.
    for forbidden in ("--install-root", "--executable", "--trusted-key", "--helper"):
        assert forbidden not in source


def test_windows_installer_stops_before_replace_and_waits_for_restart():
    source = (Path(__file__).parents[2] / "packaging" / "windows" / "bke-licensing-agent.iss").read_text(encoding="utf-8")

    assert "WaitForServiceStatus('Running'" in source
    assert "CompleteServiceStopForUpgrade" in source
    assert "Get-CimInstance -ClassName Win32_Service" in source
    assert "Where-Object Name -EQ ''{#ServiceName}''" in source
    assert "Stop-Process -Id $servicePid -Force" in source
    assert "taskkill.exe" in source
    assert "/IM bke-license-center.exe" in source
    assert "CloseApplications=yes" in source
    assert "RestartApplications=no" in source
    assert "stopped before payload replacement" in source
    assert "running after payload replacement" in source


def test_windows_legacy_recovery_never_kills_agent_by_process_name():
    source = (Path(__file__).parents[2] / "packaging" / "windows" / "bke-licensing-agent.iss").read_text(encoding="utf-8")

    assert "exact SCM PID termination" in source
    assert "Stop-Process -Name" not in source
    assert "/IM bke-licensing-agent-service.exe" not in source


def test_windows_installer_embeds_bke_proprietary_license():
    root = Path(__file__).parents[2]
    source = (root / "packaging" / "windows" / "bke-licensing-agent.iss").read_text(encoding="utf-8")
    license_text = (root / "LICENSE").read_text(encoding="utf-8")

    assert "BKE LICENSING AGENT PROPRIETARY SOFTWARE LICENSE" in license_text
    assert "All rights reserved" in license_text
    assert "LicenseFile=..\\..\\LICENSE" in source
    assert 'Source: "..\\..\\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"' in source
    assert "VersionInfoCompany={#AppPublisher}" in source
    assert "VersionInfoCopyright={#AppCopyright}" in source


def test_windows_license_center_installer_layout_matches_runtime_locator():
    root = Path(__file__).parents[2]
    installer = (root / "packaging" / "windows" / "bke-licensing-agent.iss").read_text(encoding="utf-8")
    launcher = (root / "src" / "bke_licensing_agent" / "license_center" / "native_launcher.py").read_text(encoding="utf-8")

    assert 'Source: "..\\..\\dist\\windows\\bke-license-center\\*"; DestDir: "{app}\\license-center"' in installer
    assert 'agent_dir.parent / "license-center" / name' in launcher
    assert 'startup.lpDesktop = "winsta0\\\\default"' in launcher
    assert "CreateProcessAsUserW" in launcher
    assert "Session 0" in launcher
