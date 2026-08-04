from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class DiscoveredProductRecord:
    product_id: str
    display_name: str
    version: str
    manifest_path: str
    product_root: str
    entry_point_path: str
    discovered_at: str

    @classmethod
    def from_row(cls, row: dict[str, str]) -> "DiscoveredProductRecord":
        return cls(
            product_id=row["product_id"],
            display_name=row["display_name"],
            version=row["version"],
            manifest_path=row["manifest_path"],
            product_root=row["product_root"],
            entry_point_path=row["entry_point_path"],
            discovered_at=row["discovered_at"],
        )

    @classmethod
    def create(cls, product_id: str, display_name: str, version: str, manifest_path: Path, product_root: Path, entry_point_path: Path) -> "DiscoveredProductRecord":
        return cls(
            product_id=product_id,
            display_name=display_name,
            version=version,
            manifest_path=str(manifest_path),
            product_root=str(product_root),
            entry_point_path=str(entry_point_path),
            discovered_at=(datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')),
        )
