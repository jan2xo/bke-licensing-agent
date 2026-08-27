"""Elevated Windows installer entry point for privileged updater trust state."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from bke_licensing_agent.updates.native_provisioning import (
    NativeProvisioningError,
    PrivilegedProvisioningLayout,
    provision_privileged_runtime,
)


def _require_windows() -> None:
    if os.name != "nt":
        raise NativeProvisioningError("Windows privileged provisioning must run on Windows")


def _layout() -> tuple[PrivilegedProvisioningLayout, Path, Path]:
    program_files = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
    program_data = Path(os.environ.get("ProgramData", r"C:\ProgramData"))
    install_root = program_files / "BKE Digital Solutions" / "Licensing Agent"
    data_root = program_data / "BKE Digital Solutions" / "Licensing Agent"
    privileged = data_root / "privileged"
    layout = PrivilegedProvisioningLayout(
        data_root=data_root,
        runtime_root=privileged / "runtime",
        helper_executable=install_root / "updater" / "bke-updater-core.exe",
        signing_private_key=privileged / "agent-request-signing.pem",
        target_keys_dir=privileged / "target-keys",
        target_policies_dir=privileged / "target-policies",
        approved_install_roots=(str(program_files / "BKE Digital Solutions"),),
        expected_channel="stable",
    )
    payload = install_root / "provisioning"
    return layout, payload / "target-keys", payload / "target-policies"


def _protect_windows(paths) -> None:
    """Remove inherited write authority and grant only SYSTEM/Admin full control."""
    for path in paths:
        subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", "SYSTEM:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"],
            check=True,
            capture_output=True,
            text=True,
        )


def main() -> int:
    try:
        _require_windows()
        layout, keys, policies = _layout()
        provision_privileged_runtime(
            layout,
            target_keys_source=keys,
            target_policies_source=policies,
            protect=_protect_windows,
        )
    except Exception as exc:
        print(f"BKE privileged runtime provisioning failed: {exc}", file=sys.stderr)
        return 1
    print("BKE privileged runtime provisioning complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
