import json
from pathlib import Path

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
