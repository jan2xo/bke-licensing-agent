"""Loopback-only product-to-Agent authorization API for local demonstrations.

This is intentionally a tiny adapter: products receive only an authorization
decision and never see leases, keys, credentials, or Agent storage.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import Callable
from urllib.request import Request, urlopen


class LocalAuthorizationServer:
    def __init__(self, authorize: Callable[[dict[str, str]], dict[str, object]], port: int = 0):
        self._authorize = authorize
        self._server = ThreadingHTTPServer(("127.0.0.1", port), self._handler())
        self._thread: Thread | None = None

    def _handler(self):
        authorize = self._authorize

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                if self.path != "/v1/authorize":
                    self.send_error(404)
                    return
                try:
                    length = int(self.headers.get("content-length", "0"))
                    body = json.loads(self.rfile.read(length))
                    if not isinstance(body, dict) or not all(isinstance(body.get(k), str) and body[k] for k in ("product_id", "version", "installation_id")):
                        raise ValueError("invalid authorization request")
                    result = authorize(body)
                    response = {"authorized": bool(result.get("authorized")), "reason": str(result.get("reason", ""))}
                    payload = json.dumps(response, separators=(",", ":")).encode()
                    self.send_response(200)
                    self.send_header("content-type", "application/json")
                    self.send_header("content-length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                except Exception:
                    self.send_error(400, "invalid authorization request")

            def log_message(self, *_args):
                return

        return Handler

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_port}"

    def start(self) -> "LocalAuthorizationServer":
        self._thread = Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread:
            self._thread.join(timeout=2)

    def __enter__(self):
        return self.start()

    def __exit__(self, *_args):
        self.close()


def request_authorization(base_url: str, product_id: str, version: str, installation_id: str) -> dict[str, object]:
    request = Request(
        f"{base_url.rstrip('/')}/v1/authorize",
        data=json.dumps({"product_id": product_id, "version": version, "installation_id": installation_id}).encode(),
        headers={"content-type": "application/json", "accept": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=5) as response:  # noqa: S310 - URL is loopback-only by contract.
        result = json.loads(response.read())
    if not isinstance(result, dict) or not isinstance(result.get("authorized"), bool):
        raise RuntimeError("invalid Agent authorization response")
    return result
