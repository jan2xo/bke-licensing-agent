"""Loopback-only product-to-Agent authorization, activation, and update-status boundary.

Products receive authorization decisions and secret-free update status. License keys
are submitted only to the loopback Agent; products never receive leases, signing
keys, platform credentials, update policies, download grants, or Agent storage.
"""

from __future__ import annotations

import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import Callable
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.request import Request, urlopen


MAX_JSON_BODY_BYTES = 32_768
MAX_CHUNK_LINE_BYTES = 8_192


class LocalAuthorizationServer:
    def __init__(
        self,
        authorize: Callable[[dict[str, str]], dict[str, object]],
        activate: Callable[[dict[str, str]], dict[str, object]] | None = None,
        open_license_center: Callable[[dict[str, str]], dict[str, object]] | None = None,
        update_status: Callable[[str, str], dict[str, object]] | None = None,
        refresh_update: Callable[[str, str], dict[str, object]] | None = None,
        dismiss_update: Callable[[str, str, str], dict[str, object]] | None = None,
        open_update_center: Callable[[dict[str, str]], dict[str, object]] | None = None,
        port: int = 0,
    ):
        self._authorize = authorize
        self._activate = activate
        self._open_license_center = open_license_center
        self._update_status = update_status
        self._refresh_update = refresh_update
        self._dismiss_update = dismiss_update
        self._open_update_center = open_update_center
        self._server = ThreadingHTTPServer(("127.0.0.1", port), self._handler())
        self._thread: Thread | None = None

    def _handler(self):
        authorize = self._authorize
        activate = self._activate
        open_license_center = self._open_license_center
        update_status = self._update_status
        refresh_update = self._refresh_update
        dismiss_update = self._dismiss_update
        open_update_center = self._open_update_center

        class Handler(BaseHTTPRequestHandler):
            def _json(self, status: int, body: dict[str, object]) -> None:
                payload = json.dumps(body, separators=(",", ":")).encode()
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(payload)))
                self.send_header("cache-control", "no-store")
                self.end_headers()
                self.wfile.write(payload)

            def _read_request_body(self) -> bytes | None:
                content_length = self.headers.get("content-length")
                transfer_encoding = self.headers.get("transfer-encoding")

                if content_length is not None and transfer_encoding is not None:
                    self._json(400, {"outcome": "failed", "reason": "ambiguous_request_framing"})
                    return None

                if transfer_encoding is not None:
                    codings = [value.strip().lower() for value in transfer_encoding.split(",") if value.strip()]
                    if codings != ["chunked"]:
                        self._json(400, {"outcome": "failed", "reason": "unsupported_transfer_encoding"})
                        return None

                    payload = bytearray()
                    while True:
                        size_line = self.rfile.readline(MAX_CHUNK_LINE_BYTES + 1)
                        if (not size_line or len(size_line) > MAX_CHUNK_LINE_BYTES
                                or not size_line.endswith(b"\r\n")):
                            self._json(400, {"outcome": "failed", "reason": "invalid_chunked_encoding"})
                            return None
                        size_token = size_line[:-2].split(b";", 1)[0].strip()
                        try:
                            chunk_size = int(size_token, 16)
                        except ValueError:
                            self._json(400, {"outcome": "failed", "reason": "invalid_chunked_encoding"})
                            return None

                        if chunk_size == 0:
                            while True:
                                trailer = self.rfile.readline(MAX_CHUNK_LINE_BYTES + 1)
                                if trailer == b"\r\n":
                                    return bytes(payload)
                                if (not trailer or len(trailer) > MAX_CHUNK_LINE_BYTES
                                        or not trailer.endswith(b"\r\n")):
                                    self._json(400, {"outcome": "failed", "reason": "invalid_chunked_encoding"})
                                    return None

                        if len(payload) + chunk_size > MAX_JSON_BODY_BYTES:
                            self._json(413, {"outcome": "failed", "reason": "payload_too_large"})
                            return None

                        chunk = self.rfile.read(chunk_size)
                        if len(chunk) != chunk_size or self.rfile.read(2) != b"\r\n":
                            self._json(400, {"outcome": "failed", "reason": "invalid_chunked_encoding"})
                            return None
                        payload.extend(chunk)

                if content_length is None:
                    self._json(411, {"outcome": "failed", "reason": "content_length_required"})
                    return None
                try:
                    length = int(content_length)
                except ValueError:
                    self._json(400, {"outcome": "failed", "reason": "invalid_content_length"})
                    return None
                if length < 0:
                    self._json(400, {"outcome": "failed", "reason": "invalid_content_length"})
                    return None
                if length > MAX_JSON_BODY_BYTES:
                    self._json(413, {"outcome": "failed", "reason": "payload_too_large"})
                    return None
                payload = self.rfile.read(length)
                if len(payload) != length:
                    self._json(400, {"outcome": "failed", "reason": "invalid_request_body"})
                    return None
                return payload

            def do_GET(self):  # noqa: N802
                parsed = urlparse(self.path)
                if parsed.path == "/v1/updates/status":
                    if self.headers.get("origin") is not None or update_status is None:
                        self.send_error(403 if self.headers.get("origin") is not None else 503)
                        return
                    query = parse_qs(parsed.query)
                    product_id = query.get("product_id", [""])[0]
                    version = query.get("version", [""])[0]
                    if not product_id or len(product_id) > 128 or len(version) > 64:
                        self.send_error(400)
                        return
                    self._json(200, update_status(product_id, version))
                    return
                if parsed.path != "/license-center":
                    self.send_error(404)
                    return
                query = parse_qs(parsed.query)
                values = {key: query.get(key, [""])[0] for key in ("product_id", "version", "installation_id")}
                if not all(values.values()):
                    self.send_error(400, "missing product context")
                    return
                page = f"""<!doctype html><html><head><meta charset='utf-8'><title>BKE License Center</title>
<style>body{{font-family:-apple-system,BlinkMacSystemFont,sans-serif;max-width:560px;margin:48px auto;padding:24px}}input,button{{font-size:16px;padding:10px;width:100%;box-sizing:border-box;margin:6px 0}}#status{{white-space:pre-wrap}}</style></head><body>
<h1>BKE License Center</h1><p>Activate <strong>{html.escape(values['product_id'])}</strong> version {html.escape(values['version'])} on this device.</p>
<label>License key</label><input id='key' type='password' autocomplete='off' autofocus><button id='activate'>Activate License</button><p id='status'>Waiting for license key.</p>
<script>const context={json.dumps(values)};document.getElementById('activate').onclick=async()=>{{const b=document.getElementById('activate'),s=document.getElementById('status'),k=document.getElementById('key');b.disabled=true;s.textContent='Activating…';try{{const r=await fetch('/v1/activate',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{...context,license_key:k.value}})}});const d=await r.json();s.textContent=d.authorized?'Activation successful. Return to the product and refresh authorization.':('Activation failed: '+(d.reason||'denied'));if(d.authorized)k.value='';}}catch(e){{s.textContent='Activation failed: Agent unavailable';}}finally{{b.disabled=false;}}}};</script></body></html>""".encode()
                self.send_response(200)
                self.send_header("content-type", "text/html; charset=utf-8")
                self.send_header("content-length", str(len(page)))
                self.send_header("cache-control", "no-store")
                self.end_headers()
                self.wfile.write(page)

            def do_POST(self):  # noqa: N802
                try:
                    if self.headers.get("origin") is not None:
                        self._json(403, {"outcome": "failed", "reason": "browser_origin_rejected"})
                        return
                    if self.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
                        self._json(415, {"outcome": "failed", "reason": "invalid_content_type"})
                        return
                    raw_body = self._read_request_body()
                    if raw_body is None:
                        return
                    body = json.loads(raw_body)
                    if not isinstance(body, dict):
                        raise ValueError("request must be an object")
                    if self.path == "/v1/authorize":
                        required = ("product_id", "version", "installation_id")
                        if not all(isinstance(body.get(k), str) and body[k] for k in required):
                            raise ValueError("invalid authorization request")
                        result = authorize(body)
                        response = {"authorized": bool(result.get("authorized")), "reason": str(result.get("reason", ""))}
                        if isinstance(result.get("license_center_url"), str):
                            response["license_center_url"] = result["license_center_url"]
                        self._json(200, response)
                        return
                    if self.path == "/v1/activate":
                        if activate is None:
                            self._json(503, {"authorized": False, "reason": "activation_unavailable"})
                            return
                        required = ("product_id", "version", "installation_id", "license_key")
                        if not all(isinstance(body.get(k), str) and body[k].strip() for k in required):
                            raise ValueError("invalid activation request")
                        result = activate(body)
                        self._json(200, {"authorized": bool(result.get("authorized")), "reason": str(result.get("reason", ""))})
                        return
                    if self.path == "/v1/license-center/open":
                        if open_license_center is None:
                            self._json(503, {"outcome": "agent_unavailable", "reason": "native_license_center_unavailable"})
                            return
                        required = ("product_id", "version", "installation_id", "correlation_id")
                        if not all(isinstance(body.get(k), str) and body[k].strip() for k in required):
                            raise ValueError("invalid License Center request")
                        result = open_license_center(body)
                        self._json(200, {
                            "outcome": str(result.get("outcome", "failed")),
                            "reason": str(result.get("reason", "")),
                            "authorization_changed": bool(result.get("authorization_changed")),
                            "correlation_id": str(result.get("correlation_id", body["correlation_id"])),
                        })
                        return
                    if self.path == "/v1/updates/refresh":
                        if refresh_update is None:
                            self._json(503, {"state": "refresh_failed"})
                            return
                        required = ("product_id", "version")
                        if not all(isinstance(body.get(k), str) and body[k].strip() for k in required):
                            raise ValueError("invalid refresh request")
                        self._json(202, refresh_update(body["product_id"], body["version"]))
                        return
                    if self.path == "/v1/updates/dismiss":
                        if dismiss_update is None:
                            self._json(503, {"state": "dismiss_failed"})
                            return
                        required = ("product_id", "version", "latest_version")
                        if not all(isinstance(body.get(k), str) and body[k].strip() for k in required):
                            raise ValueError("invalid dismiss request")
                        self._json(200, dismiss_update(body["product_id"], body["version"], body["latest_version"]))
                        return
                    if self.path == "/v1/update-center/open":
                        if open_update_center is None:
                            self._json(503, {"outcome": "agent_unavailable"})
                            return
                        required = ("product_id", "version", "correlation_id")
                        if not all(isinstance(body.get(k), str) and body[k].strip() for k in required):
                            raise ValueError("invalid update center request")
                        result = open_update_center(body)
                        self._json(200, {"outcome": str(result.get("outcome", "failed")),
                                         "reason": str(result.get("reason", "")),
                                         "correlation_id": str(result.get("correlation_id", body["correlation_id"]))})
                        return
                    self.send_error(404)
                except Exception:
                    self._json(400, {"authorized": False, "reason": "invalid_request"})

            def log_message(self, *_args):
                return

        return Handler

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_port}"

    def license_center_url(self, product_id: str, version: str, installation_id: str) -> str:
        return f"{self.url}/license-center?{urlencode({'product_id': product_id, 'version': version, 'installation_id': installation_id})}"

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
