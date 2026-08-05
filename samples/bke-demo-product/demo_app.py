"""Business-logic-free BKE reference product."""

import json
import signal
from pathlib import Path
from typing import Any, Callable

from bke_licensing_agent.licensing.launch_authorization import AuthorizationDecision
from bke_licensing_agent.manifest.validator import validate_manifest


def run(request_authorization: Callable[[Any], AuthorizationDecision] | None = None) -> int:
    manifest_path = Path(__file__).with_name("bke.manifest.json")
    manifest = validate_manifest(json.loads(manifest_path.read_text()))
    if request_authorization is None:
        print("Authorization: DENIED")
        print("Reason: Licensing Agent authorization service is unavailable")
        return 1
    decision = request_authorization(manifest)
    if not decision.allowed:
        print("Authorization: DENIED")
        print(f"Reason: {decision.reason.value}")
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
