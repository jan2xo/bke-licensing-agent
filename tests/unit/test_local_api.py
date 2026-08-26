import json
from urllib.request import Request, urlopen

import pytest

from bke_licensing_agent.local_api import LocalAuthorizationServer, request_authorization


def test_local_api_returns_minimal_decision_and_not_lease_data():
    with LocalAuthorizationServer(lambda request: {"authorized": request["product_id"] == "p", "reason": "ALLOW"}) as server:
        assert request_authorization(server.url, "p", "1.0.0", "installation") == {"authorized": True, "reason": "ALLOW"}
        assert request_authorization(server.url, "other", "1.0.0", "installation")["authorized"] is False


def test_local_api_rejects_malformed_requests():
    with LocalAuthorizationServer(lambda _request: {"authorized": True}) as server:
        request = Request(f"{server.url}/v1/authorize", data=json.dumps({"product_id": "p"}).encode(), headers={"content-type": "application/json"}, method="POST")
        with pytest.raises(Exception):
            urlopen(request)


def test_license_center_requires_valid_product_context_and_never_places_key_in_url():
    seen = []
    with LocalAuthorizationServer(
        lambda _request: {"authorized": False, "reason": "activation_required"},
        lambda request: seen.append(request) or {"authorized": True, "reason": "ALLOW"},
    ) as server:
        url = server.license_center_url("product-a", "1.0.0", "installation-1")
        with urlopen(url) as response:
            page = response.read().decode()
        assert "BKE License Center" in page
        assert "product-a" in page
        assert "license_key" in page
        assert "license_key=" not in url

        request = Request(
            f"{server.url}/v1/activate",
            data=json.dumps({"product_id": "product-a", "version": "1.0.0", "installation_id": "installation-1", "license_key": "secret-key"}).encode(),
            headers={"content-type": "application/json"},
            method="POST",
        )
        with urlopen(request) as response:
            result = json.loads(response.read())
        assert result == {"authorized": True, "reason": "ALLOW"}
        assert seen[0]["license_key"] == "secret-key"


def test_activation_rejects_missing_license_key():
    with LocalAuthorizationServer(lambda _request: {"authorized": False}, lambda _request: {"authorized": True}) as server:
        request = Request(
            f"{server.url}/v1/activate",
            data=json.dumps({"product_id": "p", "version": "1", "installation_id": "i"}).encode(),
            headers={"content-type": "application/json"},
            method="POST",
        )
        with pytest.raises(Exception):
            urlopen(request)


def test_native_license_center_open_returns_typed_terminal_outcome():
    seen = []
    with LocalAuthorizationServer(
        lambda _request: {"authorized": False},
        open_license_center=lambda value: seen.append(value) or {
            "outcome": "cancelled", "reason": "", "correlation_id": value["correlation_id"],
        },
    ) as server:
        request = Request(
            f"{server.url}/v1/license-center/open",
            data=json.dumps({"product_id": "p", "version": "1", "installation_id": "i",
                             "correlation_id": "corr-1"}).encode(),
            headers={"content-type": "application/json"}, method="POST",
        )
        with urlopen(request) as response:
            result = json.loads(response.read())
    assert result == {"outcome": "cancelled", "reason": "", "authorization_changed": False,
                      "correlation_id": "corr-1"}
    assert seen == [{"product_id": "p", "version": "1", "installation_id": "i",
                     "correlation_id": "corr-1"}]


def test_native_license_center_open_rejects_incomplete_context():
    with LocalAuthorizationServer(lambda _request: {"authorized": False},
                                  open_license_center=lambda _request: {"outcome": "completed"}) as server:
        request = Request(
            f"{server.url}/v1/license-center/open",
            data=json.dumps({"product_id": "p"}).encode(),
            headers={"content-type": "application/json"}, method="POST",
        )
        with pytest.raises(Exception):
            urlopen(request)


def test_update_status_is_secret_free_and_browser_origins_are_rejected():
    with LocalAuthorizationServer(lambda _request: {"authorized": True},
                                  update_status=lambda product, version: {
                                      "state": "update_available", "product_id": product,
                                      "current_version": version, "latest_version": "2.0.0"}) as server:
        with urlopen(f"{server.url}/v1/updates/status?product_id=p&version=1.0.0") as response:
            result = json.loads(response.read())
        assert result == {"state": "update_available", "product_id": "p", "current_version": "1.0.0", "latest_version": "2.0.0"}
        assert not any(key in result for key in ("download_url", "policy", "lease", "path"))
        request = Request(f"{server.url}/v1/updates/status?product_id=p&version=1.0.0",
                          headers={"origin": "https://attacker.invalid"})
        with pytest.raises(Exception): urlopen(request)
