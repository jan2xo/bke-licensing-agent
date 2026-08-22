from pathlib import Path

from bke_licensing_agent import __version__


def test_release_version_is_canonical():
    assert __version__ == "1.0.0"
    pyproject = Path(__file__).parents[2] / "pyproject.toml"
    assert 'dynamic = ["version"]' in pyproject.read_text()


def test_packaging_defaults_use_release_version():
    root = Path(__file__).parents[2]
    assert 'VERSION="${1:-1.0.0}"' in (root / "packaging/macos/build-pkg.sh").read_text()
    assert '#define AppVersion "1.0.0"' in (root / "packaging/windows/bke-licensing-agent.iss").read_text()
