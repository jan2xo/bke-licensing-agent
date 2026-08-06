from bke_licensing_agent.license_center import (
    LicenseCenterAction,
    LicenseCenterOutcome,
    LicenseCenterService,
    OpenLicenseCenterRequest,
)
from bke_licensing_agent.manifest.validator import validate_manifest


def manifest():
    return validate_manifest({
        "schemaVersion": 1, "productId": "demo", "displayName": "Demo",
        "version": "1.0.0", "entryPoint": "demo.py", "updateChannel": "stable",
        "minimumAgentVersion": "1.0.0", "platform": "linux", "architecture": "x64",
    })


def request(**changes):
    values = {"product_id": "demo", "product_version": "1.0.0",
              "action": LicenseCenterAction.ACTIVATE_LICENSE,
              "correlation_id": "corr-1", "manifest": manifest()}
    values.update(changes)
    return OpenLicenseCenterRequest(**values)


def test_valid_request_is_delegated_and_correlation_preserved():
    seen = []
    service = LicenseCenterService(lambda value: (seen.append(value), {
        "outcome": "completed", "product_id": value.product_id,
        "correlation_id": value.correlation_id, "authorization_changed": True,
    })[1])
    result = service.open_license_center(request())
    assert result.outcome is LicenseCenterOutcome.COMPLETED
    assert seen[0].action is LicenseCenterAction.ACTIVATE_LICENSE
    assert result.correlation_id == "corr-1"


def test_unvalidated_or_mismatched_context_fails_closed():
    value = manifest()
    value._validated = False
    assert service_result(request(manifest=value)).outcome is LicenseCenterOutcome.INVALID_PRODUCT_CONTEXT
    assert service_result(request(product_id="other")).outcome is LicenseCenterOutcome.INVALID_PRODUCT_CONTEXT
    assert service_result(request(product_version="2.0.0")).outcome is LicenseCenterOutcome.INCOMPATIBLE_PRODUCT_VERSION


def test_missing_launcher_is_typed_unavailable():
    result = LicenseCenterService().open_license_center(request())
    assert result.outcome is LicenseCenterOutcome.AGENT_UNAVAILABLE


def test_launcher_failure_does_not_expose_exception():
    result = LicenseCenterService(lambda _request: (_ for _ in ()).throw(RuntimeError("secret"))).open_license_center(request())
    assert result.outcome is LicenseCenterOutcome.FAILED
    assert "secret" not in result.reason


def service_result(value):
    return LicenseCenterService().open_license_center(value)
