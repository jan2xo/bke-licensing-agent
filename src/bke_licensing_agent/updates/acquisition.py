"""Bounded artifact acquisition for the Agent update boundary.

The caller supplies the server-authorized URL. This module never executes
downloaded content and verifies byte count and SHA-256 before returning it.
"""
from __future__ import annotations

import hashlib
import urllib.request
from pathlib import Path


class ArtifactAcquisitionError(ValueError):
    pass


def acquire_artifact(
    url: str,
    destination: Path,
    *,
    expected_size: int,
    expected_sha256: str,
    max_bytes: int | None = None,
) -> Path:
    if not url.startswith(("https://", "http://")):
        raise ArtifactAcquisitionError("unsupported artifact URL")
    if expected_size < 0:
        raise ArtifactAcquisitionError("invalid expected artifact size")
    limit = max_bytes if max_bytes is not None else expected_size
    if limit < expected_size:
        raise ArtifactAcquisitionError("acquisition limit below expected size")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".download")
    digest = hashlib.sha256()
    count = 0
    try:
        with urllib.request.urlopen(url, timeout=30) as response, temporary.open("wb") as output:
            announced = response.headers.get("Content-Length")
            if announced is not None and int(announced) > limit:
                raise ArtifactAcquisitionError("artifact exceeds bounded size")
            while True:
                chunk = response.read(min(1024 * 1024, limit - count + 1))
                if not chunk:
                    break
                count += len(chunk)
                if count > limit:
                    raise ArtifactAcquisitionError("artifact exceeds bounded size")
                digest.update(chunk)
                output.write(chunk)
        if count != expected_size:
            raise ArtifactAcquisitionError("artifact size mismatch")
        if digest.hexdigest().lower() != expected_sha256.lower():
            raise ArtifactAcquisitionError("artifact hash mismatch")
        temporary.replace(destination)
        return destination
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
