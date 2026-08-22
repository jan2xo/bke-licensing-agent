import json
from importlib import metadata
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import release_evidence
from scripts.release_evidence import aggregate, digest


def test_digest_and_manifest_aggregation(tmp_path: Path):
    root = tmp_path / "evidence"
    for platform, filename in (("windows-x64", "win.exe"), ("linux-x64", "linux.deb"), ("macos-arm64", "mac.pkg")):
        item = root / platform
        item.mkdir(parents=True)
        artifact = tmp_path / filename
        artifact.write_bytes(platform.encode())
        sha, size = digest(artifact)
        (item / "artifact.json").write_text(json.dumps({"platform": platform, "version": "1.0.0", "filename": filename, "sha256": sha, "size": size, "format": "deb"}))
    output = tmp_path / "out"
    aggregate(root, output, "a" * 40)
    manifest = json.loads((output / "release-manifest.json").read_text())
    assert manifest["schema"] == "bke.licensing-agent.release.v1"
    assert manifest["source"]["commit"] == "a" * 40
    assert len(manifest["artifacts"]) == 3


@pytest.fixture
def release_dependency_metadata(monkeypatch):
    requirements = {
        "bke-licensing-agent": [
            "bke-updater-core @ git+https://github.com/jan2xo/bke-updater-core.git@" + "a" * 40,
            "requests>=2.31,<3",
            "pywin32==312; sys_platform == 'win32'",
        ],
        "bke-updater-core": [],
        "requests": [],
        "pywin32": [],
    }
    versions = {
        "bke-updater-core": "0.1.0",
        "requests": "2.32.5",
        "pywin32": "312",
    }

    def distribution(name):
        key = release_evidence.canonical_name(name)
        if key not in requirements:
            raise metadata.PackageNotFoundError(name)
        return SimpleNamespace(requires=requirements[key])

    monkeypatch.setattr(release_evidence.metadata, "distribution", distribution)
    monkeypatch.setattr(
        release_evidence.metadata,
        "version",
        lambda name: versions[release_evidence.canonical_name(name)],
    )
@pytest.mark.parametrize(
    ("platform", "expects_pywin32"),
    (("windows-x64", True), ("linux-x64", False), ("macos-arm64", False)),
)
def test_platform_runtime_evidence_isolated_by_target(
    tmp_path: Path,
    monkeypatch,
    release_dependency_metadata,
    platform: str,
    expects_pywin32: bool,
):
    artifact = tmp_path / {"windows-x64": "agent.exe", "linux-x64": "agent.deb", "macos-arm64": "agent.pkg"}[platform]
    artifact.write_bytes(b"candidate")
    output = tmp_path / platform
    monkeypatch.setenv("SOURCE_SHA", "b" * 40)
    installed = [
        {"name": "bke-updater-core", "version": "0.1.0"},
        {"name": "PyInstaller", "version": "6.15.0"},
        {"name": "requests", "version": "2.32.5"},
    ]
    if platform == "windows-x64":
        installed.append({"name": "pywin32", "version": "312"})
    monkeypatch.setattr(
        release_evidence.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout=json.dumps(installed)),
    )

    release_evidence.platform_evidence(platform, artifact, output)

    inventory = json.loads((output / "dependency-inventory.json").read_text())
    runtime = {item["name"]: item for item in inventory["runtime"]}
    build_only = {release_evidence.canonical_name(item["name"]) for item in inventory["buildOnly"]}
    components = {
        item["name"]: item
        for item in json.loads((output / "sbom.cdx.json").read_text())["components"]
    }

    assert ("pywin32" in runtime) is expects_pywin32
    assert ("pywin32" in components) is expects_pywin32
    assert "pywin32" not in build_only
    assert runtime["bke-updater-core"]["internal"] is True
    assert "bke-updater-core" in components
    assert "bke-updater-core" not in build_only
    assert build_only == {"pyinstaller"}


def test_pywin32_has_one_canonical_windows_requirement():
    pyproject = (Path(__file__).parents[2] / "pyproject.toml").read_text()
    workflow = (Path(__file__).parents[2] / ".github/workflows/packaging.yml").read_text()

    assert pyproject.count("pywin32==312; sys_platform == 'win32'") == 1
    assert "pip install pyinstaller pywin32" not in workflow
