"""Bounded artifact acquisition with production transport restrictions."""
from __future__ import annotations
import hashlib
import ipaddress
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

class ArtifactAcquisitionError(ValueError): pass

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ArtifactAcquisitionError("redirects are not permitted for artifact transport")

def _approved_url(url: str, allow_loopback_http: bool) -> None:
    parsed=urllib.parse.urlparse(url)
    if parsed.scheme == "https": return
    if parsed.scheme != "http" or not allow_loopback_http or not parsed.hostname:
        raise ArtifactAcquisitionError("artifact transport requires HTTPS")
    try: loopback=ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError: loopback=parsed.hostname.lower()=="localhost"
    if not loopback: raise ArtifactAcquisitionError("HTTP is allowed only for loopback certification")

def acquire_artifact(url: str, destination: Path, *, expected_size: int,
                     expected_sha256: str, max_bytes: int | None = None,
                     allow_loopback_http: bool = False) -> Path:
    _approved_url(url, allow_loopback_http)
    if expected_size < 0 or len(expected_sha256) != 64: raise ArtifactAcquisitionError("invalid artifact bounds")
    limit=max_bytes if max_bytes is not None else expected_size
    if limit < expected_size: raise ArtifactAcquisitionError("acquisition limit below expected size")
    destination.parent.mkdir(parents=True,exist_ok=True)
    fd, temporary_name=tempfile.mkstemp(prefix="bke-artifact-",dir=str(destination.parent))
    temporary=Path(temporary_name); digest=hashlib.sha256(); count=0
    try:
        with open(fd,"wb",closefd=True) as output, urllib.request.build_opener(_NoRedirect()).open(url,timeout=30) as response:
            announced=response.headers.get("Content-Length")
            if announced is not None and int(announced)>limit: raise ArtifactAcquisitionError("artifact exceeds bounded size")
            while True:
                chunk=response.read(min(1024*1024,limit-count+1))
                if not chunk: break
                count += len(chunk)
                if count>limit: raise ArtifactAcquisitionError("artifact exceeds bounded size")
                digest.update(chunk); output.write(chunk)
        if count != expected_size: raise ArtifactAcquisitionError("artifact size mismatch")
        if digest.hexdigest().lower()!=expected_sha256.lower(): raise ArtifactAcquisitionError("artifact hash mismatch")
        temporary.replace(destination); return destination
    except Exception:
        temporary.unlink(missing_ok=True); raise
