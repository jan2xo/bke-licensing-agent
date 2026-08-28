"""Frozen executable entry point for the pinned Updater Core privileged CLI."""
from bke_updater_core.privileged_cli import main

if __name__ == "__main__":
    raise SystemExit(main())
