import base64
import json
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bke_licensing_agent.api.client import LicensingPlatformClient
from bke_licensing_agent.api.config import ApiConfig
from bke_licensing_agent.devices.fingerprint import DeviceFingerprint
from bke_licensing_agent.devices.identity import InstallationIdentity
from bke_licensing_agent.licensing.lease import LeaseVerifier, LicenseLease
from bke_licensing_agent.licensing.license_repository import LicenseRecordCorruptError, VerifiedLicenseRepository
from bke_licensing_agent.licensing.service import LicensingService
from bke_licensing_agent.manifest.validator import validate_manifest
from bke_licensing_agent.storage.database import Database


class Sessions:
    generation = 1
    def current_session(self): return object()


class Identity:
    generation = 0
    def load_or_create(self): return "installation-local-123456789012345678901234567890"


class Fingerprint:
    signals = {"platform": "linux", "architecture": "x64"}
    def calculate(self): return "d" * 64


def test_signed_platform_activation_over_real_http_persists_binding(tmp_path):
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    product = validate_manifest({"schemaVersion": 1, "productId": "bke-agent-integration-test-product", "displayName": "Test", "version": "1.0.0", "entryPoint": "app", "updateChannel": "stable", "minimumAgentVersion": "1.0.0", "platform": "linux", "architecture": "x64"})
    now = datetime.now(timezone.utc)
    lease = LicenseLease(license_id="license-local", lease_id="lease-local-1", generation=1, server_revision=1, product_id=product.productId, installation_id=Identity().load_or_create(), device_id=Fingerprint().calculate(), version=product.version, issuer="local-test", issued_at=now, not_before=now - timedelta(minutes=1), expires_at=now + timedelta(hours=1), key_id="local-test-key", algorithm="Ed25519")
    payload = lease.model_dump_json()
    envelope = {"payload": payload, "signature": base64.b64encode(private.sign(payload.encode())).decode(), "key_id": "local-test-key", "algorithm": "Ed25519"}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            assert self.path == "/api/licenses/activate"
            assert self.headers["x-bke-licensing-version"] == "bke.licensing.v2"
            body = json.loads(self.rfile.read(int(self.headers["content-length"])))
            assert body["licenseKey"] == "local-test-license"
            response = json.dumps({"lease": envelope}).encode()
            self.send_response(201); self.send_header("content-type", "application/json"); self.send_header("content-length", str(len(response))); self.end_headers(); self.wfile.write(response)
        def log_message(self, *_args): return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True); thread.start()
    db = Database(tmp_path / "agent.db")
    try:
        client = LicensingPlatformClient(ApiConfig(base_url=f"http://127.0.0.1:{server.server_port}", environment="test", allow_insecure_local=True, retry_count=0))
        repository = VerifiedLicenseRepository(db)
        service = LicensingService(client, Sessions(), Identity(), Fingerprint())
        decision = service.activate(product, "local-test-license", LeaseVerifier({"local-test-key": public}), repository)
        assert decision.authorized
        record = repository.load("license-local")
        binding = repository.active(product.productId, Identity().load_or_create(), Fingerprint().calculate())
        assert record and record.license_id == "license-local" and record.lease_id == "lease-local-1"
        assert binding and binding.active_license_id == "license-local" and binding.active_lease_id == "lease-local-1"
        db.close()
        restarted = Database(tmp_path / "agent.db")
        reloaded = VerifiedLicenseRepository(restarted)
        verified = reloaded.verify_signed_lease("lease-local-1", LeaseVerifier({"local-test-key": public}), product_id=product.productId, installation_id=Identity().load_or_create(), device_id=Fingerprint().calculate(), version=product.version)
        assert verified.license_id == "license-local"
        restarted.connection.execute("UPDATE verified_licenses SET signed_signature='tampered' WHERE lease_id='lease-local-1'")
        restarted.connection.commit()
        try:
            reloaded.verify_signed_lease("lease-local-1", LeaseVerifier({"local-test-key": public}), product_id=product.productId, installation_id=Identity().load_or_create(), device_id=Fingerprint().calculate(), version=product.version)
            raise AssertionError("tampered persisted signature was accepted")
        except Exception as exc:
            assert isinstance(exc, LicenseRecordCorruptError) or "signature" in str(exc).lower()
        restarted.close()
    finally:
        try: db.close()
        except Exception: pass
        server.shutdown(); server.server_close(); thread.join(timeout=2)
