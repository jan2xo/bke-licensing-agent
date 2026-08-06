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


def run(agent: Any | None = None, license_center: Any | None = None,
        license_key: str | None = None) -> int:
    manifest_path = Path(__file__).with_name("bke.manifest.json")
    manifest = validate_manifest(json.loads(manifest_path.read_text()))
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
    print("Press Ctrl+C to exit.")
    try:
        signal.pause()
    except KeyboardInterrupt:
        pass
    print("BKE Demo Product shutting down")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
