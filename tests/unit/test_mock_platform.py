import importlib.util
from pathlib import Path
import pytest
from bke_licensing_agent.licensing.lease import LeaseVerifier, LeaseInvalidSignatureError, LeaseUnknownKeyError, LeaseMalformedError

spec = importlib.util.spec_from_file_location("mock_platform", Path(__file__).parents[2] / "certification" / "mock_platform.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
MockActivationState, MockBKEPlatform = module.MockActivationState, module.MockBKEPlatform


@pytest.mark.parametrize("key", ["BKE-DEMO-VALID"])
def test_valid_demo_key_returns_authorized_typed_response(key):
    response = MockBKEPlatform().activate(key)
    assert response.state is MockActivationState.AUTHORIZED
    assert response.signed_lease and response.signed_lease["payload"]
    lease = LeaseVerifier({"certification-test": MockBKEPlatform.trusted_public_key()}).verify(response.signed_lease)
    assert lease.product_id == "bke-demo-product"


def test_altered_signed_mock_lease_fails_verification():
    envelope = MockBKEPlatform.signed_lease()
    envelope["signature"] = "bad"
    with pytest.raises((LeaseInvalidSignatureError, LeaseMalformedError)):
        LeaseVerifier({"certification-test": MockBKEPlatform.trusted_public_key()}).verify(envelope)


def test_unknown_certification_key_fails_verification():
    envelope = MockBKEPlatform.signed_lease()
    envelope["key_id"] = "unknown"
    with pytest.raises(LeaseUnknownKeyError):
        LeaseVerifier({"certification-test": MockBKEPlatform.trusted_public_key()}).verify(envelope)


@pytest.mark.parametrize("key", ["BKE-DEMO-INVALID", "BKE-DEMO-EXPIRED", "BKE-DEMO-REVOKED",
    "BKE-DEMO-SUSPENDED", "BKE-DEMO-DEVICE-LIMIT", "BKE-DEMO-WRONG-PRODUCT", "BKE-DEMO-WRONG-DEVICE", "BKE-DEMO-MALFORMED"])
def test_denied_demo_scenarios_fail_closed(key):
    assert MockBKEPlatform().activate(key).state is MockActivationState.DENIED


def test_arbitrary_product_is_denied():
    response = MockBKEPlatform().activate("BKE-DEMO-VALID", "other-product")
    assert response.state is MockActivationState.DENIED
