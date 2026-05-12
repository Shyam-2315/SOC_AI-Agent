#!/usr/bin/env python
"""Windows Event Log collector for the AI SOC platform.

The agent reads Windows Event Log channels, converts selected events to the
AI SOC collector ingestion schema, and posts batches to /collector/ingest.
"""

from __future__ import annotations

import argparse
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import re
import sys
import threading
import time
from typing import Any
import xml.etree.ElementTree as ET

import requests

try:
    import pywintypes
    import win32evtlog
except ImportError:  # pywin32 is only available on Windows.
    pywintypes = None
    win32evtlog = None


AGENT_DIR = Path(__file__).resolve().parent
CONFIG_PATH = AGENT_DIR / "config.json"
CONFIG_EXAMPLE_PATH = AGENT_DIR / "config.example.json"
XML_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

SECURITY_EVENT_IDS = (4625, 4624, 4688, 4720, 4722, 4728)
POWERSHELL_EVENT_IDS = (4103, 4104, 4105, 4106)
DEFENDER_EVENT_IDS = (1116, 1117, 1118, 1119, 1120)

CHANNELS = [
    {
        "name": "Security",
        "event_ids": SECURITY_EVENT_IDS,
    },
    {
        "name": "Microsoft-Windows-PowerShell/Operational",
        "event_ids": POWERSHELL_EVENT_IDS,
    },
    {
        "name": "Microsoft-Windows-Windows Defender/Operational",
        "event_ids": DEFENDER_EVENT_IDS,
    },
]

SUSPICIOUS_POWERSHELL_PATTERNS = (
    "encodedcommand",
    "frombase64string",
    "downloadstring",
    "invoke-expression",
    "iex ",
    "webclient",
    "bypass",
    "hidden",
    "nop",
)


class ConfigError(RuntimeError):
    pass


def load_config() -> dict[str, Any]:
    if not CONFIG_PATH.exists():
        raise ConfigError(
            "Missing config.json. Create it from config.example.json, then set "
            "backend_url and collector_token. Example: "
            f"Copy-Item {CONFIG_EXAMPLE_PATH.name} config.json"
        )

    with CONFIG_PATH.open("r", encoding="utf-8") as handle:
        config = json.load(handle)

    required = (
        "backend_url",
        "collector_token",
        "source_name",
        "polling_interval_seconds",
        "batch_size",
        "logs_directory",
        "state_file",
    )
    missing = [key for key in required if not config.get(key)]
    if missing:
        raise ConfigError(f"config.json is missing required field(s): {', '.join(missing)}")

    config["polling_interval_seconds"] = int(config["polling_interval_seconds"])
    config["batch_size"] = int(config["batch_size"])
    config["logs_directory"] = resolve_agent_path(config["logs_directory"])
    config["state_file"] = resolve_agent_path(config["state_file"])
    return config


def resolve_agent_path(value: str) -> str:
    path = Path(value)
    if path.is_absolute():
        return str(path)
    return str((AGENT_DIR / path).resolve())


def setup_logging(logs_directory: str) -> None:
    log_dir = Path(logs_directory)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "collector.log"

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.handlers.clear()

    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )
    file_handler = RotatingFileHandler(
        log_path,
        maxBytes=5 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    root.addHandler(file_handler)
    root.addHandler(console_handler)


def ingest_url(backend_url: str) -> str:
    normalized = backend_url.rstrip("/")
    if normalized.endswith("/collector/ingest"):
        return normalized
    return f"{normalized}/collector/ingest"


def load_state(state_file: str) -> dict[str, Any]:
    path = Path(state_file)
    if not path.exists():
        return {"channels": {}}
    try:
        with path.open("r", encoding="utf-8") as handle:
            state = json.load(handle)
        if not isinstance(state.get("channels"), dict):
            state["channels"] = {}
        return state
    except Exception:
        logging.exception("failed to load state file; starting from empty state")
        return {"channels": {}}


def save_state(state_file: str, state: dict[str, Any]) -> None:
    path = Path(state_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    with temp_path.open("w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2, sort_keys=True)
    os.replace(temp_path, path)


def event_query(event_ids: tuple[int, ...], last_record_id: int) -> str:
    id_clause = " or ".join(f"EventID={event_id}" for event_id in event_ids)
    if last_record_id > 0:
        return f"*[System[({id_clause}) and EventRecordID>{last_record_id}]]"
    return f"*[System[({id_clause})]]"


def event_text(fields: dict[str, str]) -> str:
    values = []
    for key in (
        "TargetUserName",
        "SubjectUserName",
        "IpAddress",
        "WorkstationName",
        "NewProcessName",
        "CommandLine",
        "ParentProcessName",
        "ScriptBlockText",
        "HostApplication",
        "Threat Name",
        "Path",
        "Message",
    ):
        value = fields.get(key)
        if value:
            values.append(f"{key}={value}")
    return "; ".join(values)


def normalize_ip(value: str | None) -> str:
    candidate = (value or "").strip()
    if not candidate or candidate == "-":
        return "127.0.0.1"
    if candidate.startswith("::ffff:"):
        candidate = candidate.removeprefix("::ffff:")
    try:
        import ipaddress

        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        return "127.0.0.1"


def compact_message(prefix: str, event: dict[str, Any]) -> str:
    details = event_text(event["data"])
    base = (
        f"{prefix}; channel={event['channel']}; event_id={event['event_id']}; "
        f"record_id={event['record_id']}"
    )
    if details:
        return f"{base}; {details}"
    return base


def is_suspicious_powershell(event: dict[str, Any]) -> bool:
    data = event["data"]
    haystack = " ".join(str(value) for value in data.values()).lower()
    return any(pattern in haystack for pattern in SUSPICIOUS_POWERSHELL_PATTERNS)


def transform_event(event: dict[str, Any], source_name: str) -> dict[str, str] | None:
    event_id = event["event_id"]
    channel = event["channel"]
    data = event["data"]
    ip_address = normalize_ip(data.get("IpAddress") or data.get("SourceAddress"))

    if channel == "Security":
        if event_id == 4625:
            return {
                "source": source_name,
                "event_type": "windows_failed_login",
                "severity": "high",
                "message": compact_message("Windows failed login", event),
                "ip_address": ip_address,
            }
        if event_id == 4624:
            return {
                "source": source_name,
                "event_type": "windows_successful_login",
                "severity": "low",
                "message": compact_message("Windows successful login", event),
                "ip_address": ip_address,
            }
        if event_id == 4688:
            return {
                "source": source_name,
                "event_type": "windows_process_execution",
                "severity": "medium",
                "message": compact_message("Windows process execution", event),
                "ip_address": ip_address,
            }
        if event_id in {4720, 4722, 4728}:
            return {
                "source": source_name,
                "event_type": "windows_account_change",
                "severity": "high",
                "message": compact_message("Windows account or group change", event),
                "ip_address": ip_address,
            }
        return {
            "source": source_name,
            "event_type": "windows_security_event",
            "severity": "low",
            "message": compact_message("Windows security event", event),
            "ip_address": ip_address,
        }

    if channel == "Microsoft-Windows-PowerShell/Operational":
        if not is_suspicious_powershell(event):
            return None
        return {
            "source": source_name,
            "event_type": "windows_powershell_activity",
            "severity": "high",
            "message": compact_message("Suspicious PowerShell activity", event),
            "ip_address": ip_address,
        }

    if channel == "Microsoft-Windows-Windows Defender/Operational":
        return {
            "source": source_name,
            "event_type": "windows_defender_threat",
            "severity": "critical",
            "message": compact_message("Windows Defender threat event", event),
            "ip_address": ip_address,
        }

    return None


def parse_event_xml(xml_text: str, channel_name: str) -> dict[str, Any]:
    root = ET.fromstring(xml_text)
    system = root.find("e:System", XML_NS)
    if system is None:
        raise ValueError("event XML has no System element")

    event_id = int(system.findtext("e:EventID", default="0", namespaces=XML_NS))
    record_id = int(system.findtext("e:EventRecordID", default="0", namespaces=XML_NS))
    provider = system.find("e:Provider", XML_NS)
    provider_name = provider.attrib.get("Name", "") if provider is not None else ""
    event_channel = system.findtext("e:Channel", default=channel_name, namespaces=XML_NS)
    created = system.find("e:TimeCreated", XML_NS)
    created_at = created.attrib.get("SystemTime", "") if created is not None else ""

    data: dict[str, str] = {}
    for index, node in enumerate(root.findall(".//e:EventData/e:Data", XML_NS)):
        key = node.attrib.get("Name") or f"Data{index}"
        data[key] = node.text or ""

    for node in root.findall(".//e:UserData//", XML_NS):
        tag = re.sub(r"^\{.*\}", "", node.tag)
        if node.text and tag not in data:
            data[tag] = node.text

    return {
        "channel": event_channel,
        "provider": provider_name,
        "event_id": event_id,
        "record_id": record_id,
        "created_at": created_at,
        "data": data,
    }


class WindowsCollector:
    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.state = load_state(config["state_file"])
        self.url = ingest_url(config["backend_url"])
        self.session = requests.Session()
        self.log = logging.getLogger("windows_collector")

    def require_windows_event_api(self) -> None:
        if win32evtlog is None:
            raise RuntimeError(
                "pywin32 is required for Windows Event Log collection. "
                "Install dependencies with: python -m pip install -r requirements.txt"
            )

    def collect_channel(
        self,
        channel: dict[str, Any],
        remaining: int,
    ) -> tuple[list[dict[str, str]], int]:
        self.require_windows_event_api()
        channel_name = channel["name"]
        last_record_id = int(self.state["channels"].get(channel_name, 0))
        query = event_query(channel["event_ids"], last_record_id)
        flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection
        logs: list[dict[str, str]] = []
        max_record_id = last_record_id

        try:
            handle = win32evtlog.EvtQuery(channel_name, flags, query)
        except Exception as exc:
            self.log.warning("event channel unavailable: %s: %s", channel_name, exc)
            return logs, max_record_id

        try:
            while len(logs) < remaining:
                try:
                    events = win32evtlog.EvtNext(handle, min(remaining - len(logs), 25), 1000)
                except Exception as exc:
                    if pywintypes is not None and getattr(exc, "winerror", None) == 259:
                        break
                    raise
                if not events:
                    break

                for raw_event in events:
                    xml_text = win32evtlog.EvtRender(raw_event, win32evtlog.EvtRenderEventXml)
                    event = parse_event_xml(xml_text, channel_name)
                    max_record_id = max(max_record_id, int(event["record_id"]))
                    transformed = transform_event(event, self.config["source_name"])
                    if transformed is not None:
                        logs.append(transformed)
                    if len(logs) >= remaining:
                        break
        except Exception:
            self.log.exception("failed while reading channel: %s", channel_name)
        return logs, max_record_id

    def collect_once(self) -> tuple[list[dict[str, str]], dict[str, int]]:
        logs: list[dict[str, str]] = []
        channel_positions: dict[str, int] = {}
        remaining = int(self.config["batch_size"])

        for channel in CHANNELS:
            if remaining <= 0:
                break
            channel_logs, max_record_id = self.collect_channel(channel, remaining)
            logs.extend(channel_logs)
            channel_positions[channel["name"]] = max_record_id
            remaining = int(self.config["batch_size"]) - len(logs)

        return logs, channel_positions

    def send_logs(self, logs: list[dict[str, str]]) -> bool:
        if not logs:
            return True

        payload = {"logs": logs}
        headers = {
            "Content-Type": "application/json",
            "X-Collector-Token": self.config["collector_token"],
        }
        for attempt in range(1, 4):
            try:
                response = self.session.post(self.url, json=payload, headers=headers, timeout=20)
                if response.ok:
                    self.log.info("sent %s log(s) to %s", len(logs), self.url)
                    return True
                self.log.warning(
                    "backend rejected batch attempt=%s status=%s body=%s",
                    attempt,
                    response.status_code,
                    response.text[:500],
                )
            except requests.RequestException:
                self.log.exception("failed sending batch attempt=%s", attempt)
            time.sleep(min(2**attempt, 10))
        return False

    def mark_positions(self, positions: dict[str, int]) -> None:
        for channel_name, record_id in positions.items():
            current = int(self.state["channels"].get(channel_name, 0))
            if record_id > current:
                self.state["channels"][channel_name] = record_id
        save_state(self.config["state_file"], self.state)

    def run_once(self) -> bool:
        logs, positions = self.collect_once()
        if self.send_logs(logs):
            self.mark_positions(positions)
            return True
        self.log.warning("send failed; state was not advanced so events can retry")
        return False

    def send_test_event(self) -> bool:
        log = {
            "source": self.config["source_name"],
            "event_type": "windows_security_event",
            "severity": "low",
            "message": "AI SOC Windows Collector synthetic test event",
            "ip_address": "127.0.0.1",
        }
        return self.send_logs([log])

    def run_forever(self, stop_event: threading.Event | None = None) -> None:
        self.log.info("AI SOC Windows Collector started; backend=%s", self.url)
        while True:
            if stop_event is not None and stop_event.is_set():
                break
            self.run_once()
            interval = int(self.config["polling_interval_seconds"])
            if stop_event is not None:
                stop_event.wait(interval)
            else:
                time.sleep(interval)
        self.log.info("AI SOC Windows Collector stopped")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AI SOC Windows Collector")
    parser.add_argument("--test", action="store_true", help="send one synthetic test event and exit")
    parser.add_argument("--once", action="store_true", help="collect and send one batch, then exit")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        config = load_config()
    except ConfigError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    setup_logging(config["logs_directory"])
    collector = WindowsCollector(config)

    try:
        if args.test:
            return 0 if collector.send_test_event() else 1
        if args.once:
            return 0 if collector.run_once() else 1
        collector.run_forever()
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception:
        logging.exception("collector failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
