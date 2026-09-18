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
    assert "Stop-Service -Name ''{#ServiceName}''" in source
    assert "Get-Process -Id $servicePid -ErrorAction SilentlyContinue" in source
    assert "$processGone" in source
    assert "Stop-Process -Id $servicePid -Force" in source
    assert source.index("$servicePid=[int]$legacy.ProcessId") < source.index("Stop-Service -Name")
    assert "taskkill.exe" in source
    assert "/IM bke-license-center.exe" in source
    assert "CloseApplications=yes" in source
    assert "RestartApplications=no" in source
    assert "process exited before runtime replacement" in source
    assert "local API healthy after payload replacement" in source


def test_windows_legacy_recovery_never_kills_agent_by_process_name():
    source = (Path(__file__).parents[2] / "packaging" / "windows" / "bke-licensing-agent.iss").read_text(encoding="utf-8")

    assert "$servicePid=[int]$legacy.ProcessId" in source
    assert "Get-Process -Id $servicePid -ErrorAction SilentlyContinue" in source
    assert "Stop-Process -Id $servicePid -Force" in source
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


def test_windows_canonical_installer_is_gen2_runtime_bridge_without_cert_marker():
    root = Path(__file__).parents[2]
    x64 = (root / "packaging" / "windows" / "bke-licensing-agent.iss").read_text(encoding="utf-8")
    arm64 = (root / "packaging" / "windows" / "bke-licensing-agent-arm64.iss").read_text(encoding="utf-8")

    for source in (x64, arm64):
        assert '#define AppVersion "2.0.0"' in source
        assert "bke-licensing-agent-runtime" in source
        assert "HadPreviousServicePayload" in source
        assert "LocalApiHealthy" in source
        assert "RestoreRollbackPayloads" in source
        assert "DeleteFile(ExpandConstant('{app}\\bridge-cert.enable'))" in source
        assert "SaveStringToFile(ExpandConstant('{app}\\bridge-cert.enable')" not in source
        assert 'sc.exe' in source
        assert 'BKE_AGENT_DATA_DIR' in source

    assert "bke-licensing-agent-service\\*" in x64
    assert "bke-licensing-agent-runtime\\*" in x64
    assert "Windows-x64" in x64
    assert "ArchitecturesAllowed=x64compatible" in x64

    assert "bke-licensing-agent-service-arm64\\*" in arm64
    assert "bke-licensing-agent-runtime-arm64\\*" in arm64
    assert "Windows-arm64" in arm64
    assert "ArchitecturesAllowed=arm64" in arm64


def test_windows_canonical_installer_packages_public_update_authority_keys_only():
    root = Path(__file__).parents[2]
    x64 = (root / "packaging" / "windows" / "bke-licensing-agent.iss").read_text(encoding="utf-8")
    arm64 = (root / "packaging" / "windows" / "bke-licensing-agent-arm64.iss").read_text(encoding="utf-8")

    expected_source = 'dist\\windows\\update-authority-keys\\*.json'
    expected_destination = '{app}\\trust\\update-authority-keys'
    for source in (x64, arm64):
        assert expected_source in source
        assert expected_destination in source
        assert "update-authority-keys" in source


def test_gen2_self_update_requires_signed_policy_and_exact_artifact_identity():
    root = Path(__file__).parents[2]
    verifier = (
        root / "dotnet" / "src" / "BKE.LicensingAgent.Bootstrap" / "SignedUpdatePolicy.cs"
    ).read_text(encoding="utf-8")
    worker = (
        root / "dotnet" / "src" / "BKE.LicensingAgent.Bootstrap" / "AgentSelfUpdateWorker.cs"
    ).read_text(encoding="utf-8")

    assert 'SignatureAlgorithm.Ed25519' in verifier
    assert 'bke.update-policy.v1' in verifier
    assert 'UpdatePolicyRevisionStore' in verifier
    assert 'VerifyArtifact' in verifier
    assert 'FixedTimeEquals' in verifier
    assert 'UpdatePolicyVerifier.ParseAndVerify' in worker
    assert 'UpdatePolicyVerifier.VerifyArtifact' in worker
    assert 'ValidateCatalogUrl' not in worker


def test_windows_gen2_self_update_is_native_architecture_aware():
    source = (
        Path(__file__).parents[2]
        / "dotnet"
        / "src"
        / "BKE.LicensingAgent.Bootstrap"
        / "AgentSelfUpdateWorker.cs"
    ).read_text(encoding="utf-8")

    assert 'Architecture.X64 => ("x86_64", "x64")' in source
    assert 'Architecture.Arm64 => ("arm64", "arm64")' in source
    assert "targetArchitecture.QueryValue" in source
    assert "targetArchitecture.AssetSuffix" in source
