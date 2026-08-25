from pathlib import Path
from types import SimpleNamespace

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
