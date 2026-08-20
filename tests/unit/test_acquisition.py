import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from pathlib import Path
import pytest
from bke_licensing_agent.updates.acquisition import ArtifactAcquisitionError, acquire_artifact

class Handler(BaseHTTPRequestHandler):
    payload=b"verified-artifact"
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Length",str(len(self.payload))); self.end_headers(); self.wfile.write(self.payload)
    def log_message(self,*_args): pass

@pytest.fixture
def server():
    instance=ThreadingHTTPServer(("127.0.0.1",0),Handler); thread=Thread(target=instance.serve_forever,daemon=True); thread.start()
    yield f"http://127.0.0.1:{instance.server_port}/artifact"; instance.shutdown(); thread.join()

def test_acquisition_verifies_bytes(server,tmp_path:Path):
    payload=Handler.payload
    out=acquire_artifact(server,tmp_path/"artifact",expected_size=len(payload),expected_sha256=hashlib.sha256(payload).hexdigest(),allow_loopback_http=True)
    assert out.read_bytes()==payload

def test_acquisition_rejects_hash_and_leaves_no_partial(server,tmp_path:Path):
    with pytest.raises(ArtifactAcquisitionError): acquire_artifact(server,tmp_path/"artifact",expected_size=len(Handler.payload),expected_sha256="0"*64,allow_loopback_http=True)
    assert not (tmp_path/"artifact").exists()

def test_acquisition_rejects_oversized_response(server,tmp_path:Path):
    with pytest.raises(ArtifactAcquisitionError): acquire_artifact(server,tmp_path/"artifact",expected_size=1,expected_sha256="0"*64,allow_loopback_http=True)
