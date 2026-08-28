from pathlib import Path
from types import SimpleNamespace

import bke_licensing_agent.license_center.native_launcher as native_launcher
from bke_licensing_agent.license_center.native_launcher import NativeLicenseCenterLauncher
from bke_licensing_agent.license_center.service import (
    LicenseCenterAction, LicenseCenterOutcome, OpenLicenseCenterRequest,
)
from bke_licensing_agent.manifest.validator import validate_manifest


def _request():
    manifest = validate_manifest({
        "schemaVersion": 1, "productId": "demo", "displayName": "Demo",
        "version": "1.0.0", "entryPoint": "demo.exe", "updateChannel": "stable",
        "minimumAgentVersion": "1.0.0", "platform": "windows", "architecture": "x64",
    })
    return OpenLicenseCenterRequest(
        product_id="demo", product_version="1.0.0",
        action=LicenseCenterAction.ACTIVATION_REQUIRED, correlation_id="corr-1",
        manifest=manifest, safe_context={"installation_id": "install-1"},
    )


def test_launcher_passes_only_non_secret_context_and_maps_success(tmp_path: Path):
    executable = tmp_path / "bke-license-center.exe"
    executable.touch()
    seen = []
    launcher = NativeLicenseCenterLauncher(
        executable, runner=lambda args, **kwargs: seen.append((args, kwargs)) or SimpleNamespace(returncode=0),
    )
    result = launcher(_request())
    assert result.outcome is LicenseCenterOutcome.AUTHORIZATION_REFRESHED
    assert result.authorization_changed is True
    assert seen[0][1] == {"shell": False, "check": False}
    command = tuple(seen[0][0])
    assert "demo" in command and "install-1" in command and "corr-1" in command
    assert all("license_key" not in value.lower() for value in command)


def test_launcher_maps_cancel_and_missing_binary(tmp_path: Path):
    executable = tmp_path / "bke-license-center.exe"
    result = NativeLicenseCenterLauncher(executable)(_request())
    assert result.outcome is LicenseCenterOutcome.AGENT_UNAVAILABLE
    executable.touch()
    result = NativeLicenseCenterLauncher(
        executable, runner=lambda *_args, **_kwargs: SimpleNamespace(returncode=2),
    )(_request())
    assert result.outcome is LicenseCenterOutcome.CANCELLED


def test_default_windows_path_matches_installer_layout(tmp_path: Path, monkeypatch):
    app_dir = tmp_path / "Licensing Agent"
    service_dir = app_dir / "service"
    center_dir = app_dir / "license-center"
    service_dir.mkdir(parents=True)
    center_dir.mkdir(parents=True)
    service_executable = service_dir / "bke-licensing-agent-service.exe"
    license_center = center_dir / "bke-license-center.exe"
    service_executable.touch()
    license_center.touch()

    monkeypatch.setattr(native_launcher.sys, "platform", "win32")
    monkeypatch.setattr(native_launcher.sys, "executable", str(service_executable))

    assert NativeLicenseCenterLauncher._default_executable() == license_center.resolve()


def test_windows_default_runner_uses_interactive_session_handoff(tmp_path: Path, monkeypatch):
    executable = tmp_path / "bke-license-center.exe"
    executable.touch()
    seen = []

    def interactive_runner(args, **kwargs):
        seen.append((tuple(args), kwargs))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(native_launcher.sys, "platform", "win32")
    monkeypatch.setattr(native_launcher, "_run_windows_interactive", interactive_runner)
    monkeypatch.setattr(
        native_launcher.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("Session 0 fallback is forbidden")),
    )

    result = NativeLicenseCenterLauncher(executable)(_request())

    assert result.outcome is LicenseCenterOutcome.AUTHORIZATION_REFRESHED
    assert len(seen) == 1
    assert seen[0][1] == {"shell": False, "check": False}


def test_windows_interactive_launch_failure_is_fail_closed(tmp_path: Path, monkeypatch):
    executable = tmp_path / "bke-license-center.exe"
    executable.touch()

    monkeypatch.setattr(native_launcher.sys, "platform", "win32")
    monkeypatch.setattr(
        native_launcher,
        "_run_windows_interactive",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("no active desktop")),
    )

    result = NativeLicenseCenterLauncher(executable)(_request())

    assert result.outcome is LicenseCenterOutcome.FAILED
    assert result.authorization_changed is False
