"""Windows Service entry point for the persistent Agent runtime."""

from __future__ import annotations

import servicemanager
import win32event
import win32service
import win32serviceutil

from bke_licensing_agent.runtime import InstalledAgentRuntime


class LicensingAgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = "BKE-Licensing-Agent"
    _svc_display_name_ = "BKE Licensing Agent"
    _svc_description_ = "Loopback-only BKE licensing authority."

    def __init__(self, args):
        super().__init__(args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.runtime: InstalledAgentRuntime | None = None

    def SvcStop(self):  # noqa: N802
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        if self.runtime is not None:
            self.runtime.close()
        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self):  # noqa: N802
        servicemanager.LogInfoMsg("BKE Licensing Agent service starting")
        self.runtime = InstalledAgentRuntime()
        try:
            self.runtime.serve_forever()
        finally:
            self.runtime.close()


if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(LicensingAgentService)
