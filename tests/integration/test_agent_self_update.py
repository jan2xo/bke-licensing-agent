import sys, time
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
    deadline=time.time()+5
    while time.time()<deadline and not (root/"started").exists(): time.sleep(0.05)
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

def test_real_agent_process_exits_before_helper_replacement(tmp_path):
    import subprocess, sys
    root, stage, backup = tmp_path/"agent", tmp_path/"stage", tmp_path/"backup"
    root.mkdir(); stage.mkdir()
    executable(root/"agent", root/"started", "A")
    executable(stage/"agent", root/"started", "B")
    script = """
import os, subprocess, sys
subprocess.Popen([sys.executable, "-m", "bke_updater_core.helper.main",
 "--install-root", sys.argv[1], "--staged-root", sys.argv[2],
 "--backup-root", sys.argv[3], "--executable", sys.argv[4],
 "--wait-pid", str(os.getpid())], close_fds=True)
os._exit(0)
"""
    completed=subprocess.run([sys.executable,"-c",script,str(root),str(stage),str(backup),str(root/"agent")],check=False)
    assert completed.returncode==0
    deadline=time.time()+10
    while time.time()<deadline and not (root/"started").exists(): time.sleep(0.05)
    assert (root/"agent").exists()
    assert (root/"started").read_text()=="B"
