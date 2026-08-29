from __future__ import annotations

import pytest

from bke_licensing_agent.updates.capability import (
    CAPABILITY_ID,
    CONTRACT_VERSION,
    from_discovery,
    invalid_request,
)


def test_capability_identity_matches_hardened_bke_updater_contract():
    assert CAPABILITY_ID == "bke.updates.check"
    assert CONTRACT_VERSION == 1


def test_up_to_date_and_update_available_are_minimal_and_authority_free():
    assert from_discovery({"state": "up_to_date"}) == {
        "capability_id": "bke.updates.check",
        "contract_version": 1,
        "status": "UpToDate",
        "available_version": None,
        "error": None,
    }
    result = from_discovery({
        "state": "update_available",
        "latest_version": "2.0.0",
        "policy": {"secret": "must-not-cross"},
        "download_url": "https://must-not-cross.invalid",
    })
    assert result["status"] == "UpdateAvailable"
    assert result["available_version"] == "2.0.0"
    assert not any(key in result for key in ("policy", "download_url", "lease", "signature", "path"))


@pytest.mark.parametrize("internal, public, retryable", [
    ("invalid_product_context", "InvalidRequest", False),
    ("policy_denied", "PolicyDenied", False),
    ("provider_unavailable", "ProviderUnavailable", True),
    ("transport_failure", "TransportFailure", True),
    ("protocol_failure", "ProtocolFailure", False),
    ("malformed_response", "MalformedResponse", False),
    ("verification_failure", "VerificationFailure", False),
    ("unknown", "Unknown", False),
])
def test_internal_failures_map_to_hardened_sdk_error_taxonomy(internal, public, retryable):
    result = from_discovery({"state": "refresh_failed", "error": internal})
    assert result["status"] == "Failed"
    assert result["available_version"] is None
    assert result["error"]["code"] == public
    assert result["error"]["retryable"] is retryable


def test_suppressed_internal_state_maps_to_sdk_deferred_without_exposing_suppression_details():
    result = from_discovery({
        "state": "suppressed_update",
        "latest_version": "2.0.0",
        "suppressed_until": "2026-08-30T00:00:00Z",
    })
    assert result == {
        "capability_id": "bke.updates.check",
        "contract_version": 1,
        "status": "Deferred",
        "available_version": "2.0.0",
        "error": None,
    }


def test_invalid_request_uses_sdk_failure_shape():
    result = invalid_request("unsupported request")
    assert result["status"] == "Failed"
    assert result["error"] == {
        "code": "InvalidRequest",
        "message": "unsupported request",
        "retryable": False,
    }
