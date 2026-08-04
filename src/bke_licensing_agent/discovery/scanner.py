from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from ..manifest.loader import load_manifest
from ..manifest.validator import validate_manifest
from .paths import parse_discovery_paths, resolve_manifest_entry


@dataclass
class DiscoveredProduct:
    manifest_path: Path
    product_root: Path
    manifest: dict[str, Any]
    entry_point_path: Path


def scan_locations(paths: Iterable[Path]) -> list[DiscoveredProduct]:
    discovered: list[DiscoveredProduct] = []

    for root in paths:
        if not root.exists() or not root.is_dir():
            continue

        for manifest_path in root.rglob("bke.manifest.json"):
            try:
                manifest = load_manifest(manifest_path)
                validated_manifest = validate_manifest(manifest)
                entry_point_path = resolve_manifest_entry(validated_manifest.entryPoint, manifest_path.parent)
                if not entry_point_path.exists():
                    raise ValueError("entryPoint file does not exist")

                discovered.append(
                    DiscoveredProduct(
                        manifest_path=manifest_path,
                        product_root=manifest_path.parent,
                        manifest=validated_manifest.as_dict(),
                        entry_point_path=entry_point_path,
                    )
                )
            except Exception:
                continue

    return discovered


def scan(paths: str | None = None) -> list[DiscoveredProduct]:
    return scan_locations(parse_discovery_paths(paths))
