from bke_licensing_agent.api.errors import AuthorizationDeniedError, NetworkUnavailableError
from bke_licensing_agent.licensing.diagnostics import classify_activation_failure
from bke_licensing_agent.licensing.errors import ActivationDeniedError
from bke_licensing_agent.licensing.lease import LeaseInvalidSignatureError, LeaseUnknownKeyError


def test_activation_failures_have_safe_typed_categories():
    cases = {
        NetworkUnavailableError("license-key-SECRET"): "platform_unreachable",
        AuthorizationDeniedError("bearer SECRET"): "platform_http_error",
        LeaseUnknownKeyError("private material"): "trusted_key_unavailable",
        LeaseInvalidSignatureError("signature SECRET"): "signature_verification_failed",
        ActivationDeniedError("complete lease"): "activation_rejected",
    }
    for error, category in cases.items():
        diagnostic = classify_activation_failure(error)
        assert diagnostic.category == category
        rendered = str(diagnostic.as_dict())
        assert "SECRET" not in rendered
        assert "complete lease" not in rendered


def test_diagnostic_output_contains_only_category_and_stage():
    diagnostic = classify_activation_failure(Exception("license-key-SECRET"))
    assert diagnostic.as_dict() == {"category": "unsupported_response", "stage": "activation"}
