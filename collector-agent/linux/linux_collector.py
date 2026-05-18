#!/usr/bin/env python3
"""Linux collector for the AI SOC platform.

The agent reads local Linux telemetry, maps findings to the AI SOC collector
schema, and posts batches to /collector/ingest. It performs read-only checks.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import re
import subprocess
import time
from typing import Any

import requests


AGENT_DIR = Path(__file__).resolve().parent
CONFIG_PATH = AGENT_DIR / "config.json"
CONFIG_EXAMPLE_PATH = AGENT_DIR / "config.example.json"

DEFAULT_SOURCE_IP = "127.0.0.1"
EVENT_SEVERITY = {
    "linux_ssh_failed_login": "high",
    "linux_ssh_successful_login": "low",
    "linux_invalid_user": "medium",
    "linux_sudo_command": "medium",
    "linux_sudo_failure": "high",
    "linux_suspicious_process": "high",
    "linux_docker_container_started": "low",
    "linux_docker_privileged_container": "critical",
    "linux_file_integrity_change": "critical",
    "linux_endpoint_heartbeat": "low",
    "linux_collector_test": "low",
}

FAILED_SSH_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
)
ACCEPTED_SSH_RE = re.compile(
    r"Accepted \S+ for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
)
INVALID_USER_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")
SUDO_COMMAND_RE = re.compile(r"sudo: +(?P<user>\S+) : .*COMMAND=(?P<command>.*)")
SUDO_FAILURE_RE = re.compile(
    r"sudo: .*?(authentication failure|incorrect password attempts|user NOT in sudoers)",
    re.IGNORECASE,
)

SUSPICIOUS_PROCESS_NAMES = {
    "bash",
    "sh",
    "nc",
    "netcat",
    "ncat",
    "nmap",
    "socat",
    "python",
    "python3",
    "perl",
    "ruby",
    "curl",
    "wget",
}
SUSPICIOUS_COMMAND_PATTERNS = (
    r"\b(nc|netcat|ncat)\b.*\s-e\s",
    r"/dev/tcp/",
    r"\bbash\b.*\s-i\b",
    r"\bsh\b.*\s-i\b",
    r"\bpython3?\b.*\b(socket|pty|subprocess)\b",
    r"\b(curl|wget)\b.*\|\s*(sh|bash)\b",
    r"\bnmap\b.*\s(-sS|-A|-Pn|-p)\b",
)
SUSPICIOUS_IMAGE_MARKERS = (
    "miner",
    "xmrig",
    "kali",
    "metasploit",
    "cryptominer",
    "reverse",
)


class ConfigError(RuntimeError):
    pass


def resolve_agent_path(value: str) -> str:
    path = Path(value)
    if path.is_absolute():
        return str(path)
    return str((AGENT_DIR / path).resolve())


def load_config() -> dict[str, Any]:
    if not CONFIG_PATH.exists():
        raise ConfigError(
            "Missing config.json. Copy config.example.json to config.json and set "
            f"backend_url and collector_token. Example: cp {CONFIG_EXAMPLE_PATH.name} config.json"
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
        "auth_log_paths",
        "watched_files",
        "heartbeat_interval_seconds",
    )
    missing = [key for key in required if not config.get(key)]
    if missing:
        raise ConfigError(f"config.json is missing required field(s): {', '.join(missing)}")

    config["polling_interval_seconds"] = int(config["polling_interval_seconds"])
    config["batch_size"] = int(config["batch_size"])
    config["heartbeat_interval_seconds"] = int(config["heartbeat_interval_seconds"])
    config["logs_directory"] = resolve_agent_path(config["logs_directory"])
    config["state_file"] = resolve_agent_path(config["state_file"])
    config["auth_log_paths"] = [str(Path(path)) for path in config["auth_log_paths"]]
    config["watched_files"] = [str(Path(path)) for path in config["watched_files"]]
    config.setdefault("enable_process_monitoring", True)
    config.setdefault("enable_docker_monitoring", True)
    config.setdefault("enable_file_integrity", True)
    return config


def setup_logging(logs_directory: str) -> None:
    log_dir = Path(logs_directory)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "collector.log"

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.handlers.clear()

    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
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
        return {
            "auth_logs": {},
            "file_hashes": {},
            "processes": {},
            "docker": {"known_containers": {}},
            "last_heartbeat_at": 0,
        }
    try:
        with path.open("r", encoding="utf-8") as handle:
            state = json.load(handle)
    except Exception:
        logging.exception("failed to load state file; starting from empty state")
        return load_state("__missing__")

    state.setdefault("auth_logs", {})
    state.setdefault("file_hashes", {})
    state.setdefault("processes", {})
    state.setdefault("docker", {"known_containers": {}})
    state.setdefault("last_heartbeat_at", 0)
    state["docker"].setdefault("known_containers", {})
    return state


def save_state(state_file: str, state: dict[str, Any]) -> None:
    path = Path(state_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    with temp_path.open("w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2, sort_keys=True)
    os.replace(temp_path, path)


def normalize_ip(value: str | None) -> str:
    candidate = (value or "").strip()
    if not candidate:
        return DEFAULT_SOURCE_IP
    if candidate.startswith("::ffff:"):
        candidate = candidate.removeprefix("::ffff:")
    if re.fullmatch(r"[0-9]{1,3}(\.[0-9]{1,3}){3}", candidate):
        return candidate
    if ":" in candidate and re.fullmatch(r"[0-9a-fA-F:]+", candidate):
        return candidate
    return DEFAULT_SOURCE_IP


def hostname() -> str:
    return os.uname().nodename if hasattr(os, "uname") else "linux-host"


def event(source: str, event_type: str, message: str, ip_address: str | None = None) -> dict[str, str]:
    return {
        "source": source,
        "event_type": event_type,
        "severity": EVENT_SEVERITY[event_type],
        "message": message[:4000],
        "ip_address": normalize_ip(ip_address),
    }


def transform_auth_line(line: str, source_name: str) -> dict[str, str] | None:
    invalid = INVALID_USER_RE.search(line)
    if invalid:
        user = invalid.group("user")
        ip_address = invalid.group("ip")
        return event(
            source_name,
            "linux_invalid_user",
            f"Linux invalid SSH user; user={user}; log={line.strip()}",
            ip_address,
        )

    failed = FAILED_SSH_RE.search(line)
    if failed:
        user = failed.group("user")
        ip_address = failed.group("ip")
        return event(
            source_name,
            "linux_ssh_failed_login",
            f"Linux failed SSH login; user={user}; log={line.strip()}",
            ip_address,
        )

    accepted = ACCEPTED_SSH_RE.search(line)
    if accepted:
        user = accepted.group("user")
        ip_address = accepted.group("ip")
        return event(
            source_name,
            "linux_ssh_successful_login",
            f"Linux successful SSH login; user={user}; log={line.strip()}",
            ip_address,
        )

    if SUDO_FAILURE_RE.search(line):
        return event(
            source_name,
            "linux_sudo_failure",
            f"Linux sudo failure; log={line.strip()}",
        )

    sudo_command = SUDO_COMMAND_RE.search(line)
    if sudo_command:
        user = sudo_command.group("user")
        command = sudo_command.group("command").strip()
        return event(
            source_name,
            "linux_sudo_command",
            f"Linux sudo command; user={user}; command={command}",
        )

    return None


class LinuxCollector:
    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.state = load_state(config["state_file"])
        self.url = ingest_url(config["backend_url"])
        self.session = requests.Session()
        self.log = logging.getLogger("linux_collector")

    def collect_auth_logs(self, remaining: int) -> list[dict[str, str]]:
        logs: list[dict[str, str]] = []
        source_name = self.config["source_name"]
        for raw_path in self.config["auth_log_paths"]:
            if len(logs) >= remaining:
                break
            path = Path(raw_path)
            if not path.exists():
                self.log.debug("auth log missing: %s", path)
                continue
            try:
                stat = path.stat()
                key = str(path)
                entry = self.state["auth_logs"].get(key)
                if not entry:
                    self.state["auth_logs"][key] = {
                        "offset": stat.st_size,
                        "inode": stat.st_ino,
                    }
                    continue
                offset = int(entry.get("offset", 0))
                if entry.get("inode") != stat.st_ino or stat.st_size < offset:
                    offset = 0
                with path.open("r", encoding="utf-8", errors="replace") as handle:
                    handle.seek(offset)
                    for line in handle:
                        transformed = transform_auth_line(line, source_name)
                        if transformed:
                            logs.append(transformed)
                        if len(logs) >= remaining:
                            break
                    self.state["auth_logs"][key] = {
                        "offset": handle.tell(),
                        "inode": stat.st_ino,
                    }
            except PermissionError:
                self.log.warning("permission denied reading auth log: %s", path)
            except Exception:
                self.log.exception("failed reading auth log: %s", path)
        return logs

    def collect_processes(self, remaining: int) -> list[dict[str, str]]:
        if not self.config.get("enable_process_monitoring", True) or remaining <= 0:
            return []
        try:
            result = subprocess.run(
                ["ps", "-eo", "pid=,comm=,args="],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except Exception:
            self.log.exception("failed to run read-only process listing")
            return []
        if result.returncode != 0:
            self.log.warning("process listing failed: %s", result.stderr.strip())
            return []

        logs: list[dict[str, str]] = []
        current: dict[str, str] = {}
        seen_state = self.state.setdefault("processes", {})
        for line in result.stdout.splitlines():
            parts = line.strip().split(None, 2)
            if len(parts) < 2:
                continue
            pid = parts[0]
            name = parts[1]
            args = parts[2] if len(parts) > 2 else name
            signature = hashlib.sha256(f"{name}\0{args}".encode("utf-8")).hexdigest()
            current[pid] = signature
            if seen_state.get(pid) == signature:
                continue
            if self.is_suspicious_process(name, args):
                logs.append(
                    event(
                        self.config["source_name"],
                        "linux_suspicious_process",
                        f"Linux suspicious process; pid={pid}; name={name}; command={args}",
                    )
                )
                if len(logs) >= remaining:
                    break
        self.state["processes"] = current
        return logs

    @staticmethod
    def is_suspicious_process(name: str, args: str) -> bool:
        lowered_name = Path(name).name.lower()
        lowered_args = args.lower()
        if lowered_name not in SUSPICIOUS_PROCESS_NAMES:
            return False
        return any(re.search(pattern, lowered_args) for pattern in SUSPICIOUS_COMMAND_PATTERNS)

    def collect_docker(self, remaining: int) -> list[dict[str, str]]:
        if not self.config.get("enable_docker_monitoring", True) or remaining <= 0:
            return []
        try:
            result = subprocess.run(
                ["docker", "ps", "--format", "{{json .}}"],
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except FileNotFoundError:
            self.log.debug("docker command not found; docker monitoring skipped")
            return []
        except Exception:
            self.log.exception("failed to run read-only docker ps")
            return []
        if result.returncode != 0:
            self.log.debug("docker ps unavailable: %s", result.stderr.strip())
            return []

        docker_state = self.state.setdefault("docker", {"known_containers": {}})
        known = docker_state.setdefault("known_containers", {})
        current: dict[str, str] = {}
        first_scan = not bool(known)
        logs: list[dict[str, str]] = []

        for line in result.stdout.splitlines():
            try:
                container = json.loads(line)
            except json.JSONDecodeError:
                continue
            container_id = container.get("ID")
            image = container.get("Image", "")
            names = container.get("Names", "")
            if not container_id:
                continue
            current[container_id] = image
            if first_scan or container_id in known:
                continue
            logs.extend(self.inspect_new_container(container_id, image, names))
            if len(logs) >= remaining:
                logs = logs[:remaining]
                break

        docker_state["known_containers"] = current
        return logs

    def inspect_new_container(self, container_id: str, image: str, names: str) -> list[dict[str, str]]:
        base = f"container_id={container_id}; name={names}; image={image}"
        logs = [
            event(
                self.config["source_name"],
                "linux_docker_container_started",
                f"Linux Docker container started; {base}",
            )
        ]
        lowered_image = image.lower()
        if any(marker in lowered_image for marker in SUSPICIOUS_IMAGE_MARKERS):
            logs.append(
                event(
                    self.config["source_name"],
                    "linux_suspicious_process",
                    f"Linux Docker suspicious image marker; {base}",
                )
            )
        try:
            result = subprocess.run(
                ["docker", "inspect", container_id],
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except Exception:
            self.log.exception("failed to inspect docker container: %s", container_id)
            return logs
        if result.returncode != 0:
            return logs
        try:
            inspected = json.loads(result.stdout)
        except json.JSONDecodeError:
            return logs
        if not inspected:
            return logs
        details = inspected[0]
        host_config = details.get("HostConfig", {})
        if host_config.get("Privileged"):
            logs.append(
                event(
                    self.config["source_name"],
                    "linux_docker_privileged_container",
                    f"Linux Docker privileged container; {base}",
                )
            )
        for mount in details.get("Mounts", []):
            source = str(mount.get("Source", ""))
            destination = str(mount.get("Destination", ""))
            if source in {"/", "/etc", "/var/run/docker.sock"} or source.startswith("/etc/"):
                logs.append(
                    event(
                        self.config["source_name"],
                        "linux_docker_privileged_container",
                        f"Linux Docker host filesystem mount; {base}; source={source}; destination={destination}",
                    )
                )
                break
        return logs

    def collect_file_integrity(self, remaining: int) -> list[dict[str, str]]:
        if not self.config.get("enable_file_integrity", True) or remaining <= 0:
            return []
        logs: list[dict[str, str]] = []
        file_hashes = self.state.setdefault("file_hashes", {})
        for raw_path in self.config["watched_files"]:
            if len(logs) >= remaining:
                break
            path = Path(raw_path)
            if not path.exists():
                continue
            try:
                digest = hash_file(path)
                previous = file_hashes.get(str(path))
                file_hashes[str(path)] = digest
                if previous and previous != digest:
                    logs.append(
                        event(
                            self.config["source_name"],
                            "linux_file_integrity_change",
                            f"Linux file integrity change; path={path}; sha256={digest}",
                        )
                    )
            except PermissionError:
                self.log.warning("permission denied hashing watched file: %s", path)
            except Exception:
                self.log.exception("failed hashing watched file: %s", path)
        return logs

    def collect_heartbeat(self) -> list[dict[str, str]]:
        interval = int(self.config["heartbeat_interval_seconds"])
        now = int(time.time())
        if now - int(self.state.get("last_heartbeat_at", 0)) < interval:
            return []
        self.state["last_heartbeat_at"] = now
        uptime = read_uptime()
        return [
            event(
                self.config["source_name"],
                "linux_endpoint_heartbeat",
                f"Linux endpoint heartbeat; hostname={hostname()}; platform=linux; uptime_seconds={uptime}",
            )
        ]

    def collect_once(self) -> list[dict[str, str]]:
        logs: list[dict[str, str]] = []
        batch_size = int(self.config["batch_size"])
        collectors = (
            self.collect_auth_logs,
            self.collect_processes,
            self.collect_docker,
            self.collect_file_integrity,
        )
        for collector in collectors:
            remaining = batch_size - len(logs)
            if remaining <= 0:
                break
            logs.extend(collector(remaining))
        if len(logs) < batch_size:
            logs.extend(self.collect_heartbeat()[: batch_size - len(logs)])
        return logs[:batch_size]

    def send_logs(self, logs: list[dict[str, str]]) -> tuple[bool, str]:
        if not logs:
            return True, "no logs to send"
        last_error = "unknown send failure"
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
                    return True, f"accepted status={response.status_code}"
                self.log.warning(
                    "backend rejected batch attempt=%s status=%s body=%s",
                    attempt,
                    response.status_code,
                    response.text[:500],
                )
                last_error = f"rejected status={response.status_code} body={response.text[:500]}"
            except requests.RequestException:
                self.log.exception("failed sending batch attempt=%s", attempt)
                last_error = "request error while sending"
            time.sleep(min(2**attempt, 10))
        return False, last_error

    def run_once(self) -> bool:
        previous_state = json.loads(json.dumps(self.state))
        logs = self.collect_once()
        sent, _ = self.send_logs(logs)
        if sent:
            save_state(self.config["state_file"], self.state)
            return True
        self.state = previous_state
        self.log.warning("send failed; state was not advanced so events can retry")
        return False

    def send_test_event(self) -> bool:
        log = event(
            self.config["source_name"],
            "linux_collector_test",
            f"AI SOC Linux Collector synthetic test event; hostname={hostname()}; platform=linux",
        )
        sent, reason = self.send_logs([log])
        if sent:
            print(f"Test event accepted: {reason}")
        else:
            print(f"Test event rejected: {reason}")
        return sent

    def run_forever(self) -> None:
        self.log.info("AI SOC Linux Collector started; backend=%s", self.url)
        while True:
            self.run_once()
            time.sleep(int(self.config["polling_interval_seconds"]))


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def read_uptime() -> str:
    try:
        text = Path("/proc/uptime").read_text(encoding="utf-8").split()[0]
        return str(int(float(text)))
    except Exception:
        return "unknown"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AI SOC Linux Collector")
    parser.add_argument("--test", action="store_true", help="send one synthetic test event and exit")
    parser.add_argument("--once", action="store_true", help="collect and send one batch, then exit")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        config = load_config()
    except ConfigError as exc:
        print(str(exc))
        return 2

    setup_logging(config["logs_directory"])
    collector = LinuxCollector(config)
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
