import importlib.util
from pathlib import Path


PATH = Path(__file__).parents[2] / "samples" / "bke-demo-product" / "demo_app.py"
SPEC = importlib.util.spec_from_file_location("demo_app_mapping", PATH)
demo_app = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(demo_app)


def test_demo_shortcuts_map_to_typed_action_names():
    assert demo_app.DEMO_COMMAND_ACTIONS == {
        "A": "add_license",
        "S": "select_license",
        "V": "view_licenses",
        "R": "refresh_license",
        "D": "deactivate_device",
    }


def test_quit_is_local_and_not_an_agent_action():
    assert "Q" not in demo_app.DEMO_COMMAND_ACTIONS
