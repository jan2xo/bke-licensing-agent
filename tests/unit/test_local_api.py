import json
import socket
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import pytest

from bke_licensing_agent.local_api import LocalAuthorizationServer, request_authorization


def _raw_http_request(base_url: str, request: bytes) -> tuple[bytes, dict[str, object]]:
    parsed = urlparse(base_url)
    assert parsed.hostname is not None and parsed.port is not None
    with socket.create_connection((parsed.hostname, parsed.port), timeout=2) as connection:
        connection.sendall(request)
        connection.shutdown(socket.SHUT_WR)
        response = bytearray()
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
    headers, body = bytes(response).split(b"\r\n\r\n", 1)
    return headers.split(b"\r\n", 1)[0], json.loads(body)


def _chunked_request(path: str, payload: bytes, extra_headers: bytes = b"") -> bytes:
    midpoint = max(1, len(payload) // 2)
    chunks = (payload[:midpoint], payload[midpoint:])
    encoded = b"".join(
        f"{len(chunk):X}\r\n".encode() + chunk + b"\r\n"
        for chunk in chunks if chunk
    ) + b"0\r\n\r\n"
    return (
        f"POST {path} HTTP/1.1\r\n".encode()
        + b"Host: 127.0.0.1\r\n"
        + b"Content-Type: application/json\r\n"
        + b"Transfer-Encoding: chunked\r\n"
        + extra_headers
        + b"Connection: close\r\n\r\n"
        + encoded
    )


def test_local_api_returns_minimal_decision_and_not_lease_data():
    with LocalAuthorizationServer(lambda request: {"authorized": request["product_id"] == "p", "reason": "ALLOW"}) as server:
        assert request_authorization(server.url, "p", "1.0.0", "installation") == {"authorized": True, "reason": "ALLOW"}
        assert request_authorization(server.url, "other", "1.0.0", "installation")["authorized"] is False


def test_local_api_accepts_chunked_authorization_from_desktop_clients():
    seen = []
    payload = json.dumps({
        "product_id": "bke-trial-product",
        "version": "2.0.0",
        "installation_id": "installation-1",
    }, separators=(",", ":")).encode()
    with LocalAuthorizationServer(
        lambda request: seen.append(request) or {"authorized": False, "reason": "unknown_product_or_version"}
    ) as server:
        status, body = _raw_http_request(server.url, _chunked_request("/v1/authorize", payload))

    assert status == b"HTTP/1.0 200 OK"
    assert body == {"authorized": False, "reason": "unknown_product_or_version"}
    assert seen == [{
        "product_id": "bke-trial-product",
        "version": "2.0.0",
        "installation_id": "installation-1",
    }]


def test_local_api_rejects_ambiguous_or_unsupported_request_framing():
    payload = b'{"product_id":"p","version":"1","installation_id":"i"}'
    with LocalAuthorizationServer(lambda _request: {"authorized": True, "reason": "ALLOW"}) as server:
        ambiguous = _chunked_request(
            "/v1/authorize", payload, f"Content-Length: {len(payload)}\r\n".encode()
        )
        status, body = _raw_http_request(server.url, ambiguous)
        assert status == b"HTTP/1.0 400 Bad Request"
        assert body == {"outcome": "failed", "reason": "ambiguous_request_framing"}

        unsupported = (
            b"POST /v1/authorize HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\n"
            b"Transfer-Encoding: gzip\r\n"
            b"Connection: close\r\n\r\n"
        )
        status, body = _raw_http_request(server.url, unsupported)
        assert status == b"HTTP/1.0 400 Bad Request"
        assert body == {"outcome": "failed", "reason": "unsupported_transfer_encoding"}


def test_local_api_rejects_oversized_chunked_payload_before_reading_body():
    request = (
        b"POST /v1/authorize HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Content-Type: application/json\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Connection: close\r\n\r\n"
        b"8001\r\n"
    )
    with LocalAuthorizationServer(lambda _request: {"authorized": True, "reason": "ALLOW"}) as server:
        status, body = _raw_http_request(server.url, request)
    assert status == b"HTTP/1.0 413 Request Entity Too Large"
    assert body == {"outcome": "failed", "reason": "payload_too_large"}


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


def test_update_dismissal_is_agent_owned_and_secret_free():
    seen = []
    with LocalAuthorizationServer(
        lambda _request: {"authorized": True},
        dismiss_update=lambda product, version, latest: seen.append((product, version, latest)) or {
            "state": "suppressed_update", "product_id": product, "current_version": version,
            "latest_version": latest, "suppressed_until": "2026-08-27T00:00:00Z",
        },
    ) as server:
        request = Request(
            f"{server.url}/v1/updates/dismiss",
            data=json.dumps({"product_id": "p", "version": "1.0.0", "latest_version": "2.0.0"}).encode(),
            headers={"content-type": "application/json"}, method="POST",
        )
        with urlopen(request) as response:
            result = json.loads(response.read())
    assert result["state"] == "suppressed_update"
    assert seen == [("p", "1.0.0", "2.0.0")]
    assert not any(key in result for key in ("download_url", "policy", "lease", "path"))
