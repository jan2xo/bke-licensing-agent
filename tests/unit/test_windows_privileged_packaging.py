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
