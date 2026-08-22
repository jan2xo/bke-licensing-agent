"""Generate and validate deterministic v1 release evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from importlib import metadata
from packaging.requirements import Requirement
from pathlib import Path

VERSION = "1.0.0"
SCHEMA = "bke.licensing-agent.release.v1"


def digest(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            size += len(block)
            h.update(block)
    return h.hexdigest(), size


PLATFORM_MARKER_ENVIRONMENTS = {
    "windows-x64": {"sys_platform": "win32"},
    "linux-x64": {"sys_platform": "linux"},
    "macos-arm64": {"sys_platform": "darwin"},
}


def canonical_name(name: str) -> str:
    return name.lower().replace("_", "-")


def runtime_inventory(marker_environment: dict[str, str] | None = None) -> list[dict[str, str]]:
    """Return the installed runtime dependency closure, excluding build tooling."""
    distribution = metadata.distribution("bke-licensing-agent")
    direct = []
    for requirement in distribution.requires or []:
        parsed = Requirement(requirement)
        if parsed.marker is None or parsed.marker.evaluate(environment=marker_environment):
            direct.append(parsed.name)
    wanted = {canonical_name(name): "direct" for name in direct}
    queue = list(direct)
    while queue:
        name = queue.pop(0)
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            continue
        for requirement in dist.requires or []:
            parsed = Requirement(requirement)
            if parsed.marker is not None and not parsed.marker.evaluate(environment=marker_environment):
                continue
            dep = parsed.name
            key = canonical_name(dep)
            if key not in wanted:
                wanted[key] = "transitive"
                queue.append(dep)
    result = []
    for name, kind in sorted(wanted.items()):
        try:
            version = metadata.version(name)
        except metadata.PackageNotFoundError as exc:
            raise SystemExit(f"runtime dependency is not installed: {name}") from exc
        result.append({"name": name, "version": version, "scope": kind, "internal": name == "bke-updater-core"})
    return result


def build_inventory(runtime_names: set[str]) -> list[dict[str, str]]:
    result = subprocess.run([os.environ.get("PYTHON", "python"), "-m", "pip", "list", "--format=json"], check=True, capture_output=True, text=True)
    return [
        {"name": item["name"], "version": item["version"]}
        for item in json.loads(result.stdout)
        if canonical_name(item["name"]) not in runtime_names
    ]


def platform_evidence(platform: str, artifact: Path, output: Path) -> None:
    sha, size = digest(artifact)
    output.mkdir(parents=True, exist_ok=True)
    metadata = {
        "platform": platform,
        "version": VERSION,
        "filename": artifact.name,
        "sha256": sha,
        "size": size,
        "format": {"windows-x64": "inno-setup-exe", "linux-x64": "deb", "macos-arm64": "pkg"}[platform],
        "sourceCommit": os.environ.get("SOURCE_SHA") or os.environ.get("GITHUB_SHA", ""),
        "migration": "none"
    }
    (output / "artifact.json").write_text(json.dumps(metadata, indent=2) + "\n")
    (output / "SHA256SUMS.txt").write_text(f"{sha}  {artifact.name}\n")
    runtime = runtime_inventory(PLATFORM_MARKER_ENVIRONMENTS[platform])
    runtime_names = {canonical_name(item["name"]) for item in runtime}
    components = [{"type": "library", "name": item["name"], "version": item["version"], "scope": "required"} for item in runtime]
    sbom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {"component": {"type": "application", "name": "BKE Licensing Agent", "version": VERSION}, "properties": [{"name": "platform", "value": platform}]},
        "components": components
    }
    (output / "sbom.cdx.json").write_text(json.dumps(sbom, indent=2, sort_keys=True) + "\n")
    (output / "dependency-inventory.json").write_text(json.dumps({"format": "runtime-closure", "runtime": runtime, "buildOnly": build_inventory(runtime_names)}, indent=2, sort_keys=True) + "\n")
    (output / "migration.json").write_text(json.dumps({"schema": "bke.licensing-agent.migration.v1", "migration": "none"}, indent=2) + "\n")


def aggregate(evidence_root: Path, output: Path, commit: str) -> None:
    entries = []
    for artifact_file in sorted(evidence_root.glob("*/artifact.json")):
        entries.append(json.loads(artifact_file.read_text()))
    if {item["platform"] for item in entries} != {"windows-x64", "linux-x64", "macos-arm64"}:
        raise SystemExit("release evidence must contain exactly Windows, Linux, and macOS artifacts")
    manifest = {
        "schema": SCHEMA, "version": VERSION,
        "source": {"commit": commit, "repository": "jan2xo/bke-licensing-agent"},
        "platforms": sorted(item["platform"] for item in entries),
        "artifacts": sorted(entries, key=lambda item: item["platform"]),
        "evidence": {"sbomFormat": "CycloneDX-JSON-1.5", "migration": "none", "provenance": "github-actions-attestation"}
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "release-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    (output / "SHA256SUMS.txt").write_text("".join(f"{item['sha256']}  {item['filename']}\n" for item in manifest["artifacts"]))
    (output / "migration.json").write_text(json.dumps(manifest["evidence"], indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("platform"); p.add_argument("platform"); p.add_argument("artifact", type=Path); p.add_argument("output", type=Path)
    a = sub.add_parser("aggregate"); a.add_argument("evidence_root", type=Path); a.add_argument("output", type=Path); a.add_argument("commit")
    args = parser.parse_args()
    if args.command == "platform": platform_evidence(args.platform, args.artifact, args.output)
    else: aggregate(args.evidence_root, args.output, args.commit)


if __name__ == "__main__":
    main()
