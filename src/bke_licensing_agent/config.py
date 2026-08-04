from pathlib import Path
import os

DEFAULT_DATA_DIR = Path.home() / ".local" / "share" / "bke_licensing_agent"
DATABASE_FILENAME = "agent.db"


def get_data_dir() -> Path:
    data_dir = Path(os.getenv("BKE_AGENT_DATA_DIR", DEFAULT_DATA_DIR))
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def get_database_path() -> Path:
    return get_data_dir() / DATABASE_FILENAME
