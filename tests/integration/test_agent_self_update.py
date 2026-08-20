import sys
from pathlib import Path

CORE_ROOT = Path(".ci/bke-updater-core").resolve()
if CORE_ROOT.exists():
    sys.path.insert(0, str(CORE_ROOT))
from helper.main import replace_and_launch
from helper.protocol import HelperPlan

def executable(path: Path, marker: Path, version: str, code: int = 0):
    path.write_text(
        "#!/usr/bin/env python3\n"
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text({version!r})\n"
        f"raise SystemExit({code})\n"
    )
    path.chmod(0o755)

def test_agent_a_to_b_external_helper_commit(tmp_path):
    root, stage, backup = tmp_path / "agent", tmp_path / "stage", tmp_path / "backup"
    root.mkdir(); stage.mkdir()
    executable(root / "agent", root / "started", "A")
    executable(stage / "agent", root / "started", "B")
    replace_and_launch(HelperPlan(root, stage, backup, root / "agent"))
    assert (root / "started").read_text() == "B"

def test_broken_agent_b_restores_a_and_relaunches(tmp_path):
    root, stage, backup = tmp_path / "agent", tmp_path / "stage", tmp_path / "backup"
    root.mkdir(); stage.mkdir()
    executable(root / "agent", root / "started", "A")
    original = (root / "agent").read_bytes()
    executable(stage / "agent", root / "started", "B", code=1)
    try:
        replace_and_launch(HelperPlan(root, stage, backup, root / "agent"))
    except RuntimeError:
        pass
    else:
        raise AssertionError("broken Agent B unexpectedly committed")
    assert (root / "agent").read_bytes() == original
    import subprocess
    result = subprocess.run([str(root / "agent")], check=False)
    assert result.returncode == 0
    assert (root / "started").read_text() == "A"
