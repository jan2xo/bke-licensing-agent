# macOS Setup

Requirements: Git, Python 3.12+, and a desktop session for Tk.

```bash
git clone https://github.com/jan2xo/bke-licensing-agent.git
cd bke-licensing-agent
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
pytest -q
bke-agent
bke-license-center
python samples/bke-demo-product/demo_app.py
```

Current-host packaging is verified only for macOS arm64; see
`docs/packaging-foundation.md`.
