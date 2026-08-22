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

The hosted packaging workflow builds the native Linux x64 candidate as a `.deb`.
It installs the Agent under `/opt/bke-digital-solutions/licensing-agent`, uses
systemd for boot startup, and keeps durable state under
`/var/lib/bke-digital-solutions/licensing-agent`. Native install and reboot
certification is still required before release.
