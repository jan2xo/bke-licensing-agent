import json

import pytest
import requests

from bke_licensing_agent.api.client import LicensingPlatformClient
from bke_licensing_agent.api.config import ApiConfig
from bke_licensing_agent.api.errors import (
    AuthenticationExpiredError, AuthorizationDeniedError, ConnectionTimeoutError,
    InvalidServerResponseError, RateLimitExceededError, ResourceNotFoundError,
    ServerUnavailableError,
)
from bke_licensing_agent.api.models import DeviceRegistrationRequest, LicenseVerificationRequest, PlatformLeaseActivationRequest
from bke_licensing_agent.licensing.models import ActivationRequest, ActivationVerificationRequest, DeactivationRequest


class FakeResponse:
    def __init__(self, status=200, data=None):
        self.status_code = status
        self.data = data

    def json(self):
        if isinstance(self.data, Exception):
            raise self.data
        return self.data


class FakeSession:
    def __init__(self, responses=None, error=None):
        self.responses = list(responses or [])
        self.error = error
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if self.error:
            raise self.error
        return self.responses.pop(0)


def client(session, **kwargs):
    return LicensingPlatformClient(ApiConfig(base_url="https://api.example.test", **kwargs), session, sleep=lambda _: None)


def test_valid_configuration_and_health_response():
    session = FakeSession([FakeResponse(data={"status": "ok", "service": "licensing", "version": "1"})])
    result = client(session).health()
    assert result.service == "licensing"
    assert session.calls[0][2]["verify"] is True
    assert session.calls[0][2]["timeout"] == (5.0, 15.0)
    assert "X-Request-ID" in session.calls[0][2]["headers"]


def test_configuration_rejects_missing_or_insecure_production_url():
    with pytest.raises(ValueError):
        ApiConfig(base_url="")
    with pytest.raises(ValueError, match="HTTPS"):
        ApiConfig(base_url="http://localhost:8080")


def test_configuration_allows_explicit_local_http():
    assert ApiConfig(base_url="http://localhost:8080", environment="local", allow_insecure_local=True).base_url.endswith("8080")


@pytest.mark.parametrize("method, path, model_data", [
    ("product", "product-1", {"product_id": "product-1", "display_name": "Example", "active": True}),
    ("license_status", "lic-1", {"status": "active", "license_id": "lic-1", "product_id": "product-1"}),
])
def test_typed_lookup_responses(method, path, model_data):
    session = FakeSession([FakeResponse(data=model_data)])
    result = getattr(client(session), method)(path)
    assert result


def test_request_models_serialize_for_device_and_verification():
    device_session = FakeSession([FakeResponse(data={"device_id": "dev-1", "status": "authorized"})])
    client(device_session).register_device(DeviceRegistrationRequest(device_name="Mac", device_fingerprint="hashed"))
    assert device_session.calls[0][2]["json"] == {"device_name": "Mac", "device_fingerprint": "hashed"}
    verify_session = FakeSession([FakeResponse(data={"valid": True, "status": "active", "license_id": "lic-1"})])
    client(verify_session).verify_license(LicenseVerificationRequest(product_id="p", device_id="d", installed_version="1.0.0"))
    assert verify_session.calls[0][2]["json"]["product_id"] == "p"


def test_platform_activation_request_carries_requested_product_version():
    request = PlatformLeaseActivationRequest(
        licenseKey="BKE-TEST", installationId="i" * 32, deviceId="d" * 16,
        operationId="operation-1", productVersion="1.0.0")
    assert request.model_dump()["productVersion"] == "1.0.0"


@pytest.mark.parametrize("status, error", [(401, AuthenticationExpiredError), (403, AuthorizationDeniedError),
    (404, ResourceNotFoundError), (429, RateLimitExceededError), (500, ServerUnavailableError),
    (502, ServerUnavailableError), (503, ServerUnavailableError)])
def test_status_errors_are_typed(status, error):
    with pytest.raises(error):
        client(FakeSession([FakeResponse(status=status, data={"secret": "do-not-expose"})]), retry_count=0).health()


def test_invalid_json_and_schema_are_rejected():
    with pytest.raises(InvalidServerResponseError):
        client(FakeSession([FakeResponse(data=ValueError())]), retry_count=0).health()
    with pytest.raises(InvalidServerResponseError):
        client(FakeSession([FakeResponse(data={"status": "not-valid"})]), retry_count=0).health()


def test_idempotent_requests_retry_with_bounded_count():
    session = FakeSession(error=requests.exceptions.ConnectTimeout())
    with pytest.raises(ConnectionTimeoutError):
        client(session, retry_count=2, retry_backoff=30).health()
    assert len(session.calls) == 3


def test_read_timeout_and_tls_failure_are_mapped():
    with pytest.raises(Exception) as read_error:
        client(FakeSession(error=requests.exceptions.ReadTimeout()), retry_count=0).health()
    assert read_error.value.__class__.__name__ == "RequestTimeoutError"
    with pytest.raises(Exception) as tls_error:
        client(FakeSession(error=requests.exceptions.SSLError()), retry_count=0).health()
    assert tls_error.value.__class__.__name__ == "TlsFailureError"


def test_unsafe_requests_are_not_blindly_retried():
    session = FakeSession(error=requests.exceptions.ConnectTimeout())
    with pytest.raises(ConnectionTimeoutError):
        client(session, retry_count=4).register_device(DeviceRegistrationRequest(device_name="Mac", device_fingerprint="hashed"))
    assert len(session.calls) == 1


def test_sensitive_values_are_not_in_errors():
    session = FakeSession([FakeResponse(status=403, data={"access_token": "secret", "license_key": "key"})])
    with pytest.raises(AuthorizationDeniedError) as caught:
        client(session, retry_count=0).health()
    assert "secret" not in str(caught.value)
    assert "key" not in str(caught.value)


def test_phase5_api_contract_methods_are_typed_and_non_idempotent_writes_are_not_retried():
    session = FakeSession([FakeResponse(data={"licenses": [{"license_id": "l", "product_id": "p", "status": "active"}]})])
    assert client(session).list_licenses("token")[0].license_id == "l"
    session = FakeSession([FakeResponse(data={"license_id": "l", "product_id": "p", "status": "active"})])
    assert client(session).entitlement("p", "token").product_id == "p"
    session = FakeSession([FakeResponse(data={"activation_id": "a", "license_id": "l", "product_id": "p", "device_id": "d", "status": "active"})])
    result = client(session).activate(ActivationRequest(product_id="p", license_id="l", device_id="d", installed_version="1.0.0"), "token")
    assert result.activation_id == "a" and session.calls[0][2]["headers"]["Authorization"] == "Bearer token"
    session = FakeSession([FakeResponse(data={"valid": True, "status": "active", "activation_id": "a"})])
    assert client(session).verify_activation(ActivationVerificationRequest(activation_id="a", product_id="p", device_id="d"), "token").valid
    session = FakeSession([FakeResponse(data={"success": True})])
    assert client(session).deactivate(DeactivationRequest(activation_id="a", device_id="d"), "token").success
