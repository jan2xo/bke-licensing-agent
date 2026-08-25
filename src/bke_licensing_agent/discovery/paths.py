import os
from pathlib import Path


def _default_discovery_paths() -> list[Path]:
    if os.name == "nt":
        program_files = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
        return [
            program_files / "BKE AirStack",
            program_files / "BKE Digital Solutions",
            Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
            / "Programs" / "BKE Digital Solutions",
        ]
    return [
        Path.home() / "Applications" / "BKE",
        Path("/Applications/BKE"),
        Path.home() / ".local" / "share" / "BKE",
    ]


DEFAULT_DISCOVERY_PATHS = _default_discovery_paths()


def parse_discovery_paths(paths: str | None = None) -> list[Path]:
    if paths is None:
        paths = os.getenv("BKE_DISCOVERY_PATHS", "")

    separator = ";" if os.name == "nt" else ":"
    candidates = [entry.strip() for entry in paths.split(separator) if entry.strip()]
    if not candidates:
        return list(DEFAULT_DISCOVERY_PATHS)

    return [Path(os.path.expanduser(candidate)) for candidate in candidates]


def resolve_manifest_entry(entry_point: str, manifest_dir: Path) -> Path:
    portable_entry = entry_point.replace("\\", "/")
    if portable_entry.startswith(("/", "\\")) or (len(portable_entry) >= 2 and portable_entry[1] == ":"):
        raise ValueError("entryPoint must be a relative path")

    resolved_entry = (manifest_dir / Path(*portable_entry.split("/"))).resolve()
    manifest_dir_resolved = manifest_dir.resolve()
    try:
        resolved_entry.relative_to(manifest_dir_resolved)
    except ValueError as exc:
        raise ValueError("entryPoint must not escape the product directory") from exc

    return resolved_entry
