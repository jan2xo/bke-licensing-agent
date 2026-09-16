"""Windows Service entry point for the persistent Agent runtime."""

from __future__ import annotations

import servicemanager
import sys
import threading
import win32event
import win32service
import win32serviceutil
import win32timezone

from bke_licensing_agent.config import get_data_dir, get_platform_base_url
from bke_licensing_agent.notification_runtime import NotificationEnabledAgentRuntime
from bke_licensing_agent.self_update import AgentSelfUpdateCoordinator, CHECK_INTERVAL


class LicensingAgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = "BKE-Licensing-Agent"
    _svc_display_name_ = "BKE Licensing Agent"
    _svc_description_ = "Loopback-only BKE licensing authority."

    def __init__(self, args):
        super().__init__(args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.runtime: NotificationEnabledAgentRuntime | None = None
        self.self_update_stop = threading.Event()
        self.self_update_thread: threading.Thread | None = None

    def SvcStop(self):  # noqa: N802
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.self_update_stop.set()
        if self.runtime is not None:
            self.runtime.close()
        win32event.SetEvent(self.stop_event)

    def _run_self_update_loop(self) -> None:
        coordinator = AgentSelfUpdateCoordinator(
            state_root=get_data_dir(),
            platform_base_url=get_platform_base_url(),
        )
        if self.self_update_stop.wait(5):
            return
        while not self.self_update_stop.is_set():
            try:
                outcome = coordinator.poll_once()
                if outcome == "update_started":
                    servicemanager.LogInfoMsg("BKE Licensing Agent self-update installer started")
                elif outcome == "later":
                    servicemanager.LogInfoMsg("BKE Licensing Agent self-update deferred by the active user")
            except Exception as exc:
                servicemanager.LogWarningMsg(f"BKE Licensing Agent self-update check failed: {exc}")
            if self.self_update_stop.wait(CHECK_INTERVAL.total_seconds()):
                return

    def SvcDoRun(self):  # noqa: N802
        servicemanager.LogInfoMsg("BKE Licensing Agent service starting")
        self.self_update_stop.clear()
        self.self_update_thread = threading.Thread(
            target=self._run_self_update_loop,
            daemon=True,
            name="bke-agent-self-update",
        )
        self.self_update_thread.start()
        self.runtime = NotificationEnabledAgentRuntime()
        try:
            self.runtime.serve_forever()
        finally:
            self.self_update_stop.set()
            self.runtime.close()


def _run_service_host() -> None:
    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(LicensingAgentService)
    servicemanager.StartServiceCtrlDispatcher()


if __name__ == "__main__":
    if "--service-smoke" in sys.argv[1:]:
        service_class = win32serviceutil.GetServiceClassString(LicensingAgentService)
        if not service_class.endswith(".LicensingAgentService"):
            raise RuntimeError("could not resolve frozen Windows service class")
        print(f"BKE Licensing Agent Windows service dependency smoke: win32timezone and {service_class} OK")
    elif "--service-host-smoke" in sys.argv[1:]:
        required = (
            servicemanager.Initialize,
            servicemanager.PrepareToHostSingle,
            servicemanager.StartServiceCtrlDispatcher,
        )
        if not all(callable(item) for item in required):
            raise RuntimeError("Windows service host functions are unavailable")
        print("BKE Licensing Agent Windows service host smoke: SCM host functions OK")
    elif "--smoke" in sys.argv[1:]:
        print("BKE Licensing Agent Windows service smoke: import and entrypoint OK")
    elif len(sys.argv) == 1:
        _run_service_host()
    else:
        win32serviceutil.HandleCommandLine(LicensingAgentService)
