"""Loopback-only product-to-Agent authorization and activation boundary.

Products receive authorization decisions and an Agent-owned License Center URL.
License keys are submitted only to the loopback Agent; products never receive
leases, signing keys, platform credentials, or Agent storage.
"""

from __future__ import annotations

import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import Callable
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.request import Request, urlopen


class LocalAuthorizationServer:
    def __init__(
        self,
        authorize: Callable[[dict[str, str]], dict[str, object]],
        activate: Callable[[dict[str, str]], dict[str, object]] | None = None,
        port: int = 0,
    ):
        self._authorize = authorize
        self._activate = activate
        self._server = ThreadingHTTPServer(("127.0.0.1", port), self._handler())
        self._thread: Thread | None = None

    def _handler(self):
        authorize = self._authorize
        activate = self._activate

        class Handler(BaseHTTPRequestHandler):
            def _json(self, status: int, body: dict[str, object]) -> None:
                payload = json.dumps(body, separators=(",", ":")).encode()
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(payload)))
                self.send_header("cache-control", "no-store")
                self.end_headers()
                self.wfile.write(payload)

            def do_GET(self):  # noqa: N802
                parsed = urlparse(self.path)
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
                    length = int(self.headers.get("content-length", "0"))
                    body = json.loads(self.rfile.read(length))
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
