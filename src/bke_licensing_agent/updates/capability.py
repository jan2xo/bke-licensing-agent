"""BKE.Updater contract adapter over Agent-owned update discovery.

This module is intentionally authority-free. It translates trusted Agent outcomes
into the public BKE.Updater capability vocabulary without exposing leases,
policies, grants, paths, signing keys, or privileged execution controls.
"""
from __future__ import annotations

from typing import Any


CAPABILITY_ID = "bke.updates.check"
CONTRACT_VERSION = 1

_ERROR_MAP: dict[str, tuple[str, str, bool]] = {
    "invalid_product_context": (
        "InvalidRequest",
        "The product or current version is not known to the local provider.",
        False,
    ),
    "policy_denied": (
        "PolicyDenied",
        "The trusted provider did not authorize update discovery for this product context.",
        False,
    ),
    "provider_unavailable": (
        "ProviderUnavailable",
        "The trusted update authority is temporarily unavailable.",
        True,
    ),
    "transport_failure": (
        "TransportFailure",
        "The provider could not reach the trusted update authority.",
        True,
    ),
    "protocol_failure": (
        "ProtocolFailure",
        "The provider and trusted update authority could not complete their protocol.",
        False,
    ),
    "malformed_response": (
        "MalformedResponse",
        "The trusted update authority returned an invalid response.",
        False,
    ),
    "verification_failure": (
        "VerificationFailure",
        "The provider could not verify the trusted update response.",
        False,
    ),
    "unknown": (
        "Unknown",
        "The update check failed for an unknown provider reason.",
        False,
    ),
}


def _base(status: str, *, available_version: str | None = None,
          error: dict[str, object] | None = None) -> dict[str, object]:
    return {
        "capability_id": CAPABILITY_ID,
        "contract_version": CONTRACT_VERSION,
        "status": status,
        "available_version": available_version,
        "error": error,
    }


def invalid_request(message: str) -> dict[str, object]:
    return _base(
        "Failed",
        error={"code": "InvalidRequest", "message": message, "retryable": False},
    )


def from_discovery(document: dict[str, Any]) -> dict[str, object]:
    """Translate one trusted discovery result into BKE.Updater contract v1."""
    state = document.get("state")
    if state == "up_to_date":
        return _base("UpToDate")
    if state in {"update_available", "stale_update"}:
        version = document.get("latest_version")
        if isinstance(version, str) and version.strip():
            return _base("UpdateAvailable", available_version=version)
        return _base(
            "Failed",
            error={
                "code": "MalformedResponse",
                "message": "The provider produced an update without an available version.",
                "retryable": False,
            },
        )
    if state == "suppressed_update":
        version = document.get("latest_version")
        return _base(
            "Deferred",
            available_version=version if isinstance(version, str) and version.strip() else None,
        )
    if state == "refresh_failed":
        internal_error = document.get("error")
        code, message, retryable = _ERROR_MAP.get(
            internal_error if isinstance(internal_error, str) else "unknown",
            _ERROR_MAP["unknown"],
        )
        return _base(
            "Failed",
            error={"code": code, "message": message, "retryable": retryable},
        )
    return _base(
        "Failed",
        error={
            "code": "Unknown",
            "message": "The provider returned an unsupported update state.",
            "retryable": False,
        },
    )
