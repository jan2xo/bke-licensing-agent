# Development Commands

```bash
pytest -q
bke-agent
bke-license-center
python samples/bke-demo-product/demo_app.py
python -m compileall -q src tests samples
git diff --check
python -m pip check
```

Current-host PyInstaller commands are documented in
`docs/packaging-foundation.md`. The repository does not contain
`packaging/build.py`, `verify.py`, or `clean.py`; those commands are not
documented as available.
