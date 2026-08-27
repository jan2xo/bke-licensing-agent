from __future__ import annotations

import importlib.util
import os
import subprocess
from pathlib import Path

import pytest


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows ACL certification requires Windows")


def _provisioner_module():
    path = Path(__file__).parents[2] / "packaging" / "windows" / "provision_privileged_runtime.py"
    spec = importlib.util.spec_from_file_location("bke_windows_privileged_provisioner", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_windows_acl_protection_removes_inherited_authority(tmp_path: Path):
    module = _provisioner_module()
    protected = tmp_path / "privileged"
    protected.mkdir()
    secret = protected / "agent-request-signing.pem"
    secret.write_text("fixture", encoding="utf-8")

    module._protect_windows((protected, secret))

    for path in (protected, secret):
        result = subprocess.run(["icacls", str(path)], check=True, capture_output=True, text=True)
        # Explicit ACLs installed by the provisioner are not inherited. This is
        # executed by windows-latest, so CI certifies real icacls behavior rather
        # than a mocked platform approximation.
        assert "(I)" not in result.stdout
