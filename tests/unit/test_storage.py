from pathlib import Path

from bke_licensing_agent.storage.database import Database
from bke_licensing_agent.storage.models import DiscoveredProductRecord


def test_database_saves_and_lists_records(tmp_path: Path):
    db_path = tmp_path / "agent.db"
    db = Database(path=db_path)

    record = DiscoveredProductRecord.create(
        product_id="airstack",
        display_name="AIRSTACK",
        version="1.0.0",
        manifest_path=tmp_path / "product" / "bke.manifest.json",
        product_root=tmp_path / "product",
        entry_point_path=tmp_path / "product" / "AIRSTACK.exe",
    )

    db.save_discovered_product(record)
    records = db.list_discovered_products()

    assert len(records) == 1
    assert records[0].product_id == "airstack"
    assert records[0].manifest_path.endswith("bke.manifest.json")
