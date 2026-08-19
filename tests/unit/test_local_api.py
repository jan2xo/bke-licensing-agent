import json

import pytest

from bke_licensing_agent.local_api import LocalAuthorizationServer, request_authorization


def test_local_api_returns_minimal_decision_and_not_lease_data():
    with LocalAuthorizationServer(lambda request: {"authorized": request["product_id"] == "p", "reason": "ALLOW"}) as server:
        assert request_authorization(server.url, "p", "1.0.0", "installation") == {"authorized": True, "reason": "ALLOW"}
        assert request_authorization(server.url, "other", "1.0.0", "installation")["authorized"] is False


def test_local_api_rejects_malformed_requests():
    with LocalAuthorizationServer(lambda _request: {"authorized": True}) as server:
        from urllib.request import Request, urlopen
        request = Request(f"{server.url}/v1/authorize", data=json.dumps({"product_id": "p"}).encode(), headers={"content-type": "application/json"}, method="POST")
        with pytest.raises(Exception):
            urlopen(request)
