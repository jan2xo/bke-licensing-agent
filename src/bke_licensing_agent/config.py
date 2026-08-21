from pathlib import Path
import os

DEFAULT_DATA_DIR = Path.home() / ".local" / "share" / "bke_licensing_agent"
DATABASE_FILENAME = "agent.db"
AGENT_HOST = "127.0.0.1"
DEFAULT_AGENT_PORT = 43873
TRUSTED_KEYS_DIRNAME = "trusted-keys"


def get_data_dir() -> Path:
    data_dir = Path(os.getenv("BKE_AGENT_DATA_DIR", DEFAULT_DATA_DIR))
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def get_database_path() -> Path:
    return get_data_dir() / DATABASE_FILENAME


def get_agent_port() -> int:
    raw = os.getenv("BKE_AGENT_PORT")
    if raw is None:
        return DEFAULT_AGENT_PORT
    port = int(raw)
    if not 1 <= port <= 65535:
        raise ValueError("BKE_AGENT_PORT must be between 1 and 65535")
    return port


def get_trusted_keys_dir() -> Path:
    path = get_data_dir() / TRUSTED_KEYS_DIRNAME
    path.mkdir(parents=True, exist_ok=True)
    return path
