"""Safe composition of the packaged, Agent-owned native License Center."""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

from .service import LicenseCenterOutcome, OpenLicenseCenterRequest, OpenLicenseCenterResult


class NativeLicenseCenterLauncher:
    """Launch the sibling packaged UI and wait for its typed terminal outcome."""

    def __init__(self, executable: Path | None = None, *, runner=subprocess.run):
        self.executable = executable or self._default_executable()
        self.runner = runner

    @staticmethod
    def _default_executable() -> Path:
        name = "bke-license-center.exe" if sys.platform == "win32" else "bke-license-center"
        agent_dir = Path(sys.executable).resolve().parent
        candidates = (agent_dir / name, agent_dir.parent / "bke-license-center" / name)
        return next((candidate for candidate in candidates if candidate.is_file()), candidates[0])

    def __call__(self, request: OpenLicenseCenterRequest) -> OpenLicenseCenterResult:
        if not self.executable.is_file():
            return self._result(request, LicenseCenterOutcome.AGENT_UNAVAILABLE,
                                "native License Center is not installed")
        arguments: Sequence[str] = (
            str(self.executable), "--product-id", request.product_id,
            "--product-version", request.product_version,
            "--installation-id", request.safe_context["installation_id"] if request.safe_context else "",
            "--correlation-id", request.correlation_id,
            "--action", request.action.value,
        )
        try:
            completed = self.runner(arguments, shell=False, check=False)
        except OSError:
            return self._result(request, LicenseCenterOutcome.FAILED,
                                "native License Center could not be started")
        outcomes = {
            0: LicenseCenterOutcome.AUTHORIZATION_REFRESHED,
            2: LicenseCenterOutcome.CANCELLED,
            3: LicenseCenterOutcome.ACTIVATION_FAILED,
        }
        outcome = outcomes.get(completed.returncode, LicenseCenterOutcome.FAILED)
        return self._result(request, outcome, "" if completed.returncode in outcomes else "native License Center failed")

    @staticmethod
    def _result(request, outcome, reason):
        return OpenLicenseCenterResult(
            outcome=outcome, reason=reason, product_id=request.product_id,
            correlation_id=request.correlation_id,
            authorization_changed=outcome is LicenseCenterOutcome.AUTHORIZATION_REFRESHED,
        )
