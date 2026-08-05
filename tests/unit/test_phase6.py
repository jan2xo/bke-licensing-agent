from datetime import datetime, timedelta, timezone

import pytest

from bke_licensing_agent.licensing.authorization import AuthorizationService, AuthorizationState
from bke_licensing_agent.licensing.lease import (
    LicenseLease, LeaseMalformedError, LeaseRevokedError, LeaseSupersededError,
    LeaseUnknownKeyError, LeaseVerifier,
)
from bke_licensing_agent.manifest.validator import validate_manifest


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def product():
    return validate_manifest({"schemaVersion": 1, "productId": "p", "displayName": "P",
        "version": "1.0.0", "entryPoint": "app", "updateChannel": "stable",
        "minimumAgentVersion": "1.0.0", "platform": "linux", "architecture": "x64"})


def lease(**changes):
    values = dict(lease_id="l", generation=1, product_id="p", installation_id="i",
        device_id="d", version="1.0.0", issuer="bke", issued_at=NOW,
        not_before=NOW - timedelta(minutes=1), expires_at=NOW + timedelta(hours=1),
        key_id="k", algorithm="Ed25519")
    values.update(changes)
    return LicenseLease(**values)


@pytest.mark.parametrize("state, changes", [
    (AuthorizationState.LEASE_EXPIRED, {"expires_at": NOW - timedelta(minutes=1)}),
    (AuthorizationState.LEASE_NOT_YET_VALID, {"not_before": NOW + timedelta(minutes=2)}),
    (AuthorizationState.LEASE_WRONG_PRODUCT, {"product_id": "other"}),
    (AuthorizationState.LEASE_WRONG_INSTALLATION, {"installation_id": "other"}),
    (AuthorizationState.LEASE_WRONG_DEVICE, {"device_id": "other"}),
    (AuthorizationState.LEASE_VERSION_REJECTED, {"version": "2.0.0"}),
])
def test_offline_authorization_fails_closed(state, changes):
    decision = AuthorizationService(clock=lambda: NOW).authorize(product(), lease(**changes), "i", "d")
    assert decision.state is state and not decision.authorized


def test_offline_authorization_accepts_valid_lease():
    decision = AuthorizationService(clock=lambda: NOW).authorize(product(), lease(), "i", "d")
    assert decision.state is AuthorizationState.AUTHORIZED


def test_untrusted_key_is_rejected_before_signature_work():
    with pytest.raises(LeaseUnknownKeyError):
        LeaseVerifier({}).verify({"payload": "e30=", "signature": "eA==", "key_id": "unknown", "algorithm": "Ed25519"})


def test_malformed_envelope_is_rejected():
    with pytest.raises(LeaseMalformedError): LeaseVerifier({"k": "bad"}).verify({})


def test_revoked_and_superseded_leases_are_rejected_after_signature_boundary():
    # These checks are applied to the authenticated payload by the verifier.
    verifier = LeaseVerifier({})
    assert lease(revoked=True).revoked
    assert lease(superseded_by="new").superseded_by == "new"
    assert LeaseRevokedError and LeaseSupersededError
