from threading import Thread
from time import monotonic

from bke_licensing_agent.runtime import InstalledAgentRuntime
from bke_licensing_agent.storage.database import Database


def test_runtime_close_returns_serve_forever_and_releases_loopback_server(tmp_path):
    runtime = InstalledAgentRuntime(database=Database(tmp_path / "agent.db"), port=0)
    thread = Thread(target=runtime.serve_forever)
    thread.start()

    deadline = monotonic() + 5
    while runtime._server is None and monotonic() < deadline:
        runtime._stop_event.wait(0.01)
    assert runtime._server is not None

    runtime.close()
    thread.join(timeout=3)

    assert not thread.is_alive()
    assert runtime._server is None
