import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from bke_licensing_agent.manifest.models import Manifest


def test_manifest_model_accepts_valid_manifest():
    manifest = {
        "schemaVersion": 1,
        "productId": "airstack",
        "displayName": "AIRSTACK",
        "publisher": "BKE Digital Solutions",
        "version": "1.0.0",
        "entryPoint": "AIRSTACK.exe",
        "icon": "assets/airstack.ico",
        "updateChannel": "stable",
        "minimumAgentVersion": "1.0.0",
        "platform": "windows",
        "architecture": "x64",
    }

    model = Manifest(**manifest)

    assert model.productId == "airstack"
    assert model.entryPoint == "AIRSTACK.exe"


def test_manifest_model_rejects_invalid_semver():
    manifest = {
        "schemaVersion": 1,
        "productId": "airstack",
        "displayName": "AIRSTACK",
        "publisher": "BKE Digital Solutions",
        "version": "one.zero.zero",
        "entryPoint": "AIRSTACK.exe",
        "icon": "assets/airstack.ico",
        "updateChannel": "stable",
        "minimumAgentVersion": "1.0.0",
        "platform": "windows",
        "architecture": "x64",
    }

    with pytest.raises(ValidationError, match="Invalid semantic version"):
        Manifest(**manifest)


def test_manifest_model_rejects_absolute_entry_point():
    manifest = {
        "schemaVersion": 1,
        "productId": "airstack",
        "displayName": "AIRSTACK",
        "publisher": "BKE Digital Solutions",
        "version": "1.0.0",
        "entryPoint": "/usr/bin/AIRSTACK.exe",
        "icon": "assets/airstack.ico",
        "updateChannel": "stable",
        "minimumAgentVersion": "1.0.0",
        "platform": "windows",
        "architecture": "x64",
    }

    with pytest.raises(ValidationError, match="entryPoint must be a relative path"):
        Manifest(**manifest)
