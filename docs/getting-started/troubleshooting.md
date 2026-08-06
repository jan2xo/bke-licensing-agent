# Troubleshooting

- Activate `.venv`; if commands are missing, use `.venv/bin/bke-agent` or the Windows Scripts path.
- Rerun `python -m pip install -e .` for module import errors.
- Tk errors indicate missing Tk or an unavailable graphical session.
- Use Python 3.12 or newer (`python --version`).
- PowerShell activation uses the process-scoped execution policy shown in the Windows guide.
- PyInstaller must be installed separately for bundle builds.
