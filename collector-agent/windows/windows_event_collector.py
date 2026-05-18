#!/usr/bin/env python
"""Collect Windows Security Event ID 4625 and send it to AI SOC."""

from __future__ import annotations

import argparse
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import socket
import time
from typing import Any
import xml.etree.ElementTree as ET

import requests

try:
    import pywintypes
    import win32evtlog
except ImportError:
    pywintypes = None
    win32evtlog = None


BASE_DIR = Path(__file__).resolve().parent
CONFIG_FILE = BASE_DIR / "config.json"
XML_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
DEFAULT_IP = "127.0.0.1"


def setup_logging(logs_directory: str = "logs") -> None:
    log_dir = Path(logs_directory)
    if not log_dir.is_absolute():
        log_dir = (BASE_DIR / log_dir).resolve()
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "collector.log"

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.handlers.clear()
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

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


def load_config() -> dict[str, Any]:
    if not CONFIG_FILE.exists():
        raise RuntimeError("Missing config.json. Run installer or create config.json")
    with CONFIG_FILE.open("r", encoding="utf-8") as handle:
        config = json.load(handle)

    if config.get("collector_token") and not config.get("api_token"):
        config["api_token"] = config["collector_token"]

    required = ["backend_url", "api_token", "source_name", "poll_interval_seconds", "log_name", "event_ids", "state_file"]
    missing = [key for key in required if not config.get(key)]
    if missing:
        raise RuntimeError(f"config.json missing required fields: {', '.join(missing)}")

    config["poll_interval_seconds"] = int(config["poll_interval_seconds"])
    config["event_ids"] = [int(event_id) for event_id in config["event_ids"]]
    state_file = Path(config["state_file"])
    if not state_file.is_absolute():
        state_file = BASE_DIR / state_file
    config["state_file"] = str(state_file)
    config.setdefault("logs_directory", "logs")
    return config


def load_state(path: str) -> dict[str, Any]:
    state_path = Path(path)
    if not state_path.exists():
        return {"last_record_id": 0}
    try:
        with state_path.open("r", encoding="utf-8") as handle:
            state = json.load(handle)
        return {"last_record_id": int(state.get("last_record_id", 0))}
    except Exception:
        logging.exception("Could not read state file; starting from record 0")
        return {"last_record_id": 0}


def save_state(path: str, state: dict[str, Any]) -> None:
    state_path = Path(path)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = state_path.with_suffix(state_path.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2, sort_keys=True)
    os.replace(tmp_path, state_path)


def ingest_url(backend_url: str) -> str:
    normalized = backend_url.rstrip("/")
    if normalized.endswith("/collector/ingest"):
        return normalized
    return f"{normalized}/collector/ingest"


def event_query(event_ids: list[int], last_record_id: int) -> str:
    ids = " or ".join(f"EventID={event_id}" for event_id in event_ids)
    if last_record_id > 0:
        return f"*[System[({ids}) and EventRecordID>{last_record_id}]]"
    return f"*[System[({ids})]]"


def parse_event(xml_text: str, fallback_channel: str) -> dict[str, Any]:
    root = ET.fromstring(xml_text)
    system = root.find("e:System", XML_NS)
    if system is None:
        raise ValueError("event XML missing System element")

    provider = system.find("e:Provider", XML_NS)
    created = system.find("e:TimeCreated", XML_NS)
    data: dict[str, str] = {}
    for index, node in enumerate(root.findall(".//e:EventData/e:Data", XML_NS)):
        key = node.attrib.get("Name") or f"Data{index}"
        data[key] = node.text or ""

    return {
        "event_id": int(system.findtext("e:EventID", default="0", namespaces=XML_NS)),
        "provider": provider.attrib.get("Name", "") if provider is not None else "",
        "record_id": int(system.findtext("e:EventRecordID", default="0", namespaces=XML_NS)),
        "timestamp": created.attrib.get("SystemTime", "") if created is not None else "",
        "channel": system.findtext("e:Channel", default=fallback_channel, namespaces=XML_NS),
        "computer": system.findtext("e:Computer", default=socket.gethostname(), namespaces=XML_NS),
        "fields": data,
    }


def normalize_ip(value: str | None) -> str:
    candidate = (value or "").strip()
    if not candidate or candidate == "-":
        return DEFAULT_IP
    if candidate.startswith("::ffff:"):
        candidate = candidate.removeprefix("::ffff:")
    return candidate


def first_field(fields: dict[str, str], *names: str) -> str | None:
    for name in names:
        value = fields.get(name)
        if value and value != "-":
            return value
    return None


def safe_raw_event(event: dict[str, Any]) -> dict[str, Any]:
    fields = event["fields"]
    return {
        "event_id": event["event_id"],
        "provider": event["provider"],
        "record_id": event["record_id"],
        "timestamp": event["timestamp"],
        "channel": event["channel"],
        "computer": event["computer"],
        "fields": {str(key): str(value)[:1000] for key, value in fields.items()},
    }


def to_soc_log(event: dict[str, Any], source_name: str) -> dict[str, Any]:
    fields = event["fields"]
    hostname = event.get("computer") or socket.gethostname()
    username = first_field(fields, "TargetUserName", "AccountName")
    domain = first_field(fields, "TargetDomainName", "AccountDomain")
    source_ip = normalize_ip(first_field(fields, "IpAddress", "SourceNetworkAddress"))
    logon_type = first_field(fields, "LogonType")
    workstation_name = first_field(fields, "WorkstationName", "Workstation")
    failure_reason = first_field(fields, "FailureReason")
    status = first_field(fields, "Status")
    substatus = first_field(fields, "SubStatus")
    process_name = first_field(fields, "ProcessName", "CallerProcessName")
    message = (
        "Windows failed login detected; "
        f"host={hostname}; username={username or 'unknown'}; domain={domain or 'unknown'}; "
        f"source_ip={source_ip}; "
        f"logon_type={logon_type or 'unknown'}; record_id={event['record_id']}"
    )
    return {
        "source": source_name,
        "event_type": "windows_failed_login",
        "severity": "medium",
        "message": message,
        "ip_address": source_ip,
        "timestamp": event["timestamp"],
        "hostname": hostname,
        "host": hostname,
        "event_id": event["event_id"],
        "provider": event["provider"],
        "record_id": event["record_id"],
        "logon_type": logon_type,
        "username": username,
        "domain": domain,
        "source_ip": source_ip,
        "workstation_name": workstation_name,
        "failure_reason": failure_reason,
        "status": status,
        "substatus": substatus,
        "process_name": process_name,
        "raw_event": safe_raw_event(event),
    }


class WindowsEventCollector:
    def __init__(self, config: dict[str, Any]) -> None:
        if win32evtlog is None:
            raise RuntimeError("pywin32 is required. Run: pip install -r requirements.txt")
        self.config = config
        self.state = load_state(config["state_file"])
        self.url = ingest_url(config["backend_url"])
        self.session = requests.Session()

    def collect_once(self) -> tuple[list[dict[str, Any]], int]:
        last_record_id = int(self.state.get("last_record_id", 0))
        query = event_query(self.config["event_ids"], last_record_id)
        flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection
        try:
            handle = win32evtlog.EvtQuery(self.config["log_name"], flags, query)
        except Exception as exc:
            if pywintypes is not None and getattr(exc, "winerror", None) == 5:
                raise RuntimeError(
                    "Access denied reading Windows Security log. "
                    "Open PowerShell as Administrator and run the collector again."
                ) from exc
            raise
        logs: list[dict[str, Any]] = []
        max_record_id = last_record_id

        while True:
            try:
                events = win32evtlog.EvtNext(handle, 25, 1000)
            except Exception as exc:
                if pywintypes is not None and getattr(exc, "winerror", None) == 259:
                    break
                raise
            if not events:
                break
            for raw_event in events:
                try:
                    xml_text = win32evtlog.EvtRender(raw_event, win32evtlog.EvtRenderEventXml)
                    event = parse_event(xml_text, self.config["log_name"])
                    max_record_id = max(max_record_id, int(event["record_id"]))
                    if int(event["event_id"]) == 4625:
                        logs.append(to_soc_log(event, self.config["source_name"]))
                except Exception as exc:
                    logging.warning("Skipping malformed Windows event: %s", exc)

        return logs, max_record_id

    def send_logs(self, logs: list[dict[str, Any]]) -> tuple[bool, str]:
        if not logs:
            return True, "no logs to send"
        headers = {
            "Content-Type": "application/json",
            "X-Collector-Token": self.config["api_token"],
        }
        payload = {"logs": logs}
        last_error = ""
        for attempt in range(1, 4):
            try:
                response = self.session.post(self.url, headers=headers, json=payload, timeout=20)
                if response.ok:
                    logging.info("Sent %s Windows failed-login event(s)", len(logs))
                    return True, f"accepted status={response.status_code}"
                last_error = f"rejected status={response.status_code} body={response.text[:500]}"
                logging.warning("Backend rejected batch attempt=%s %s", attempt, last_error)
            except requests.RequestException as exc:
                last_error = f"request error: {exc}"
                logging.warning("Send failed attempt=%s error=%s", attempt, exc)
            time.sleep(min(2**attempt, 10))
        return False, last_error or "unknown send failure"

    def send_test_event(self) -> tuple[bool, str]:
        event = {
            "source": self.config["source_name"],
            "event_type": "windows_collector_test",
            "severity": "low",
            "message": f"AI SOC Windows collector synthetic test event; host={socket.gethostname()}",
            "ip_address": DEFAULT_IP,
        }
        return self.send_logs([event])

    def poll_once(self) -> None:
        try:
            logs, max_record_id = self.collect_once()
        except RuntimeError:
            raise
        except Exception as exc:
            logging.warning("Windows event collection failed; will retry: %s", exc)
            return
        if logs:
            logging.info("Detected %s Event ID 4625 record(s)", len(logs))
        else:
            logging.info("No new Event ID 4625 records")
        sent, reason = self.send_logs(logs)
        if sent:
            self.state["last_record_id"] = max_record_id
            save_state(self.config["state_file"], self.state)
        else:
            logging.warning("State not advanced because backend send failed: %s", reason)

    def run(self) -> None:
        logging.info("Windows Event ID 4625 collector started; backend=%s", self.url)
        while True:
            self.poll_once()
            time.sleep(self.config["poll_interval_seconds"])


def main() -> int:
    parser = argparse.ArgumentParser(description="AI SOC Windows collector")
    parser.add_argument("--test", action="store_true", help="send synthetic test event and exit")
    args = parser.parse_args()

    try:
        config = load_config()
        setup_logging(config.get("logs_directory", "logs"))
        collector = WindowsEventCollector(config)
        if args.test:
            sent, reason = collector.send_test_event()
            if sent:
                print(f"Test event accepted: {reason}")
                return 0
            print(f"Test event rejected: {reason}")
            return 1
        collector.run()
        return 0
    except KeyboardInterrupt:
        logging.info("Collector stopped")
        return 0
    except Exception as exc:
        logging.error("%s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
