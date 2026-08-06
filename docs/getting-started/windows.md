# Windows Setup

Requirements: Git, Python 3.12+, and VS Code (recommended).

```powershell
git clone https://github.com/jan2xo/bke-licensing-agent.git
cd bke-licensing-agent
py -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
pytest -q
bke-agent
bke-license-center
python samples\bke-demo-product\demo_app.py
```

Windows native packaging is not verified here.
