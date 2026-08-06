# Linux Setup

Requirements: Git, Python 3.12+, and a desktop session with Tk. Headless GUI
activation is not supported by this milestone.

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

Linux packaging is planned and not verified here.
