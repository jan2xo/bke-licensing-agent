from __future__ import annotations

import pytest

from bke_licensing_agent.api.client import LicensingPlatformClient
from bke_licensing_agent.api.config import ApiConfig
from bke_licensing_agent.api.errors import (
    AuthorizationDeniedError,
    ServerUnavailableError,
    UpdateProtocolError,
    UpdateVerificationError,
)
from bke_licensing_agent.api.models import UpdateDiscoveryRequest


class FakeResponse:
    def __init__(self, status: int, data: dict[str, object]):
        self.status_code = status
        self.data = data

    def json(self):
        return self.data


class FakeSession:
    def __init__(self, response: FakeResponse):
        self.response = response

    def request(self, *_args, **_kwargs):
        return self.response


def _request() -> UpdateDiscoveryRequest:
    return UpdateDiscoveryRequest(
        lease={"payload": "{}", "signature": "sig", "key_id": "k", "algorithm": "Ed25519"},
        product_id="p",
        current_version="1.0.0",
        platform="windows",
        architecture="x64",
        channel="stable",
    )


def _client(status: int, error: str) -> LicensingPlatformClient:
    return LicensingPlatformClient(
        ApiConfig(base_url="https://api.example.test", retry_count=0),
        FakeSession(FakeResponse(status, {"error": error})),  # type: ignore[arg-type]
        sleep=lambda _seconds: None,
    )


@pytest.mark.parametrize("remote_error", ["RELEASE_NOT_VERIFIED", "INVALID_ARTIFACT_CONTRACT"])
def test_remote_release_verification_errors_are_not_collapsed(remote_error):
    with pytest.raises(UpdateVerificationError):
        _client(503, remote_error).check_update(_request())


@pytest.mark.parametrize("remote_error", ["INVALID_REQUEST", "INVALID_CONTENT_TYPE"])
def test_remote_protocol_errors_are_not_collapsed(remote_error):
    with pytest.raises(UpdateProtocolError):
        _client(400, remote_error).check_update(_request())


def test_remote_policy_denial_stays_policy_denial():
    with pytest.raises(AuthorizationDeniedError):
        _client(403, "UPDATE_NOT_ENTITLED").check_update(_request())


def test_unclassified_remote_server_failure_stays_provider_unavailable():
    with pytest.raises(ServerUnavailableError):
        _client(500, "UPDATE_DISCOVERY_FAILED").check_update(_request())
