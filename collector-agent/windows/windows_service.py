#!/usr/bin/env python
"""Windows service wrapper for AI SOC Windows collector."""

from __future__ import annotations

import logging
import threading

try:
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil
except ImportError as exc:
    raise SystemExit(
        "pywin32 is required to install/run the service. Install with: py -3 -m pip install -r requirements.txt"
    ) from exc

from windows_event_collector import WindowsEventCollector, load_config, setup_logging


class AISOCWindowsCollectorService(win32serviceutil.ServiceFramework):
    _svc_name_ = "AISOCWindowsCollector"
    _svc_display_name_ = "AI SOC Windows Collector"
    _svc_description_ = "Collects Windows security telemetry and sends it to AI SOC."

    def __init__(self, args):
        super().__init__(args)
        self.stop_handle = win32event.CreateEvent(None, 0, 0, None)
        self.stop_event = threading.Event()

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.stop_event.set()
        win32event.SetEvent(self.stop_handle)

    def SvcDoRun(self):
        servicemanager.LogInfoMsg("AI SOC Windows Collector service starting")
        try:
            config = load_config()
            setup_logging(config.get("logs_directory", "logs"))
            collector = WindowsEventCollector(config)
            while not self.stop_event.is_set():
                collector.poll_once()
                self.stop_event.wait(config["poll_interval_seconds"])
        except Exception:
            logging.exception("AI SOC Windows Collector service failed")
            servicemanager.LogErrorMsg("AI SOC Windows Collector service failed")
            raise
        finally:
            servicemanager.LogInfoMsg("AI SOC Windows Collector service stopped")


if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(AISOCWindowsCollectorService)
