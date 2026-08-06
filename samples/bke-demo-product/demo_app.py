"""Business-logic-free BKE reference product."""

import json
import signal
import sys
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from bke_licensing_agent.manifest.validator import validate_manifest

DEMO_COMMAND_ACTIONS = {
    "A": "add_license",
    "S": "select_license",
    "V": "view_licenses",
    "R": "refresh_license",
    "D": "deactivate_device",
}


def create_certification_agent() -> Any:
    from certification.agent import CertificationAgent
    return CertificationAgent()


def create_license_center(agent: Any) -> Any:
    from bke_licensing_agent.license_center.controller import LicenseCenterController
    return LicenseCenterController(agent)


def launch_license_center(controller: Any, manifest: Any) -> Any:
    from bke_licensing_agent.license_center.app import run as run_license_center
    run_license_center(controller, manifest)
    return controller.state


def run_license_command(agent: Any, manifest: Any, action: str) -> Any:
    from bke_licensing_agent.license_center.app import run as run_license_center
    from bke_licensing_agent.license_center.controller import LicenseCenterController
    from bke_licensing_agent.license_center.service import (
        LicenseCenterAction, LicenseCenterOutcome, LicenseCenterService,
        OpenLicenseCenterRequest,
    )

    action_map = {"A": LicenseCenterAction.ADD_LICENSE, "S": LicenseCenterAction.SELECT_LICENSE,
                  "V": LicenseCenterAction.VIEW_LICENSES, "R": LicenseCenterAction.REFRESH_LICENSE,
                  "D": LicenseCenterAction.DEACTIVATE_DEVICE}
    request = OpenLicenseCenterRequest(product_id=manifest.productId,
        product_version=manifest.version, action=action_map[action],
        correlation_id=f"demo-{action.lower()}", manifest=manifest)
    controller = LicenseCenterController(agent)

    def launcher(_request):
        run_license_center(controller, manifest, mode=_request.action.value)
        return {"outcome": "completed", "product_id": manifest.productId,
                "correlation_id": _request.correlation_id, "authorization_changed": True}

    result = LicenseCenterService(launcher).open_license_center(request)
    if result.outcome is not LicenseCenterOutcome.COMPLETED:
        print(f"License Center: {result.reason or result.outcome.value}")
    return result


def run(agent: Any | None = None, license_center: Any | None = None,
        license_key: str | None = None) -> int:
    manifest_path = Path(__file__).with_name("bke.manifest.json")
    manifest = validate_manifest(json.loads(manifest_path.read_text()))
    interactive = agent is None
    if agent is None:
        agent = create_certification_agent()
    if license_center is None:
        license_center = create_license_center(agent)
    try:
        decision = agent.authorize(manifest)
    except Exception as exc:
        if str(exc) != "activation_required":
            print("Authorization: DENIED")
            print("Reason: authorization_unavailable")
            return 1
        if license_key is not None:
            license_center.connect()
            license_center.sign_in(license_key)
            license_center.select_product(manifest)
            state = license_center.activate()
        else:
            state = launch_license_center(license_center, manifest)
        if state.screen.value != "status":
            print("Authorization: DENIED")
            print(f"Reason: {state.error or 'activation_denied'}")
            return 1
        decision = agent.authorize(manifest)
    if decision is None or not getattr(decision, "authorized", False) and not getattr(decision, "allowed", False):
        print("Authorization: DENIED")
        print("Reason: activation_required or authorization_denied")
        return 1
    print("===================================")
    print("BKE Demo Product")
    print("===================================")
    print(f"Product: {manifest.productId}")
    print(f"Version: {manifest.version}")
    print("Authorization: AUTHORIZED")
    print("Status: RUNNING")
    print(f"Edition: {getattr(decision, 'edition', None) or 'Unknown'}")
    print("Commands: A Add, S Select, V View, R Refresh, D Deactivate, Q Quit")
    print("Press Ctrl+C to exit.")
    try:
        if interactive:
            while True:
                try:
                    command = input("License command: ").strip().upper()
                except (EOFError, OSError):
                    break
                if command == "Q":
                    break
                if command in {"A", "S", "V", "R", "D"}:
                    run_license_command(agent, manifest, command)
                    try:
                        decision = agent.authorize(manifest)
                        print(f"Edition: {getattr(decision, 'edition', None) or 'Unknown'}")
                    except Exception as exc:
                        print(f"Authorization unavailable: {type(exc).__name__}")
                else:
                    print("Use A, S, V, R, D, or Q")
        else:
            signal.pause()
    except KeyboardInterrupt:
        pass
    print("BKE Demo Product shutting down")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
