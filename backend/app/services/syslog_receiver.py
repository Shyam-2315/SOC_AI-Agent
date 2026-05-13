from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass
from datetime import datetime
import ipaddress
import logging
import re
import socket
from typing import Any

from app.core.config import settings
from app.schemas.collector import CollectorIngestBatch
from app.services.collectors import authenticate_collector_token, ingest_collector_batch


logger = logging.getLogger("syslog_receiver")

RFC3164_RE = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?:(?P<program>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s*)?"
    r"(?P<message>.*)$"
)
RFC5424_RE = re.compile(
    r"^(?P<version>\d+)\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<program>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<structured_data>-|\[.*?\])\s*"
    r"(?P<message>.*)$"
)
PRI_RE = re.compile(r"^<(?P<priority>\d{1,3})>(?P<body>.*)$", re.DOTALL)


@dataclass(frozen=True)
class SyslogMessage:
    raw: str
    priority: int | None
    timestamp: str | None
    hostname: str | None
    program: str | None
    message: str
    source_ip: str | None = None


def _safe_ip(value: str | None) -> str:
    if not value:
        return "127.0.0.1"
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return "127.0.0.1"


def syslog_priority_to_severity(priority: int | None) -> str:
    if priority is None:
        return "low"
    syslog_severity = priority & 7
    if syslog_severity <= 2:
        return "critical"
    if syslog_severity == 3:
        return "high"
    if syslog_severity == 4:
        return "medium"
    return "low"


def parse_syslog_message(raw: str, source_ip: str | None = None) -> SyslogMessage:
    text = raw.strip()
    priority = None
    body = text
    priority_match = PRI_RE.match(text)
    if priority_match:
        try:
            priority = int(priority_match.group("priority"))
        except ValueError:
            priority = None
        body = priority_match.group("body").strip()

    rfc5424 = RFC5424_RE.match(body)
    if rfc5424:
        hostname = rfc5424.group("hostname")
        program = rfc5424.group("program")
        return SyslogMessage(
            raw=text,
            priority=priority,
            timestamp=_none_if_dash(rfc5424.group("timestamp")),
            hostname=_none_if_dash(hostname),
            program=_none_if_dash(program),
            message=rfc5424.group("message").strip() or body,
            source_ip=source_ip,
        )

    rfc3164 = RFC3164_RE.match(body)
    if rfc3164:
        return SyslogMessage(
            raw=text,
            priority=priority,
            timestamp=rfc3164.group("timestamp"),
            hostname=_none_if_dash(rfc3164.group("hostname")),
            program=_none_if_dash(rfc3164.group("program")),
            message=rfc3164.group("message").strip() or body,
            source_ip=source_ip,
        )

    return SyslogMessage(
        raw=text,
        priority=priority,
        timestamp=None,
        hostname=None,
        program=None,
        message=body,
        source_ip=source_ip,
    )


def _none_if_dash(value: str | None) -> str | None:
    if not value or value == "-":
        return None
    return value


def syslog_to_collector_log(message: SyslogMessage) -> dict[str, str]:
    source_ip = _safe_ip(message.source_ip)
    source = message.hostname or source_ip
    details = []
    if message.timestamp:
        details.append(f"timestamp={message.timestamp}")
    if message.program:
        details.append(f"program={message.program}")
    details.append(f"message={message.message}")
    return {
        "source": source,
        "event_type": "syslog_event",
        "severity": syslog_priority_to_severity(message.priority),
        "message": "; ".join(details),
        "ip_address": source_ip,
    }


class SyslogDatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self, queue: asyncio.Queue[dict[str, Any]]):
        self.queue = queue

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        raw = data.decode("utf-8", errors="replace")
        source_ip = addr[0] if addr else None
        try:
            message = parse_syslog_message(raw, source_ip)
            self.queue.put_nowait(syslog_to_collector_log(message))
        except asyncio.QueueFull:
            logger.warning("syslog queue full; dropping message from %s", source_ip)
        except Exception:
            logger.exception("failed to parse syslog message from %s", source_ip)


async def _flush_batch(queue: asyncio.Queue[dict[str, Any]], batch_size: int) -> list[dict[str, Any]]:
    batch = [await queue.get()]
    deadline = asyncio.get_running_loop().time() + 1.0
    while len(batch) < batch_size:
        timeout = max(0.0, deadline - asyncio.get_running_loop().time())
        if timeout <= 0:
            break
        try:
            batch.append(await asyncio.wait_for(queue.get(), timeout=timeout))
        except asyncio.TimeoutError:
            break
    return batch


async def run_syslog_receiver() -> None:
    if not settings.syslog_enabled:
        logger.info("syslog receiver disabled; set SYSLOG_ENABLED=true to enable it")
        while True:
            await asyncio.sleep(3600)

    if not settings.syslog_collector_token:
        raise RuntimeError("SYSLOG_COLLECTOR_TOKEN is required when SYSLOG_ENABLED=true")

    collector = await authenticate_collector_token(settings.syslog_collector_token)
    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=10000)
    loop = asyncio.get_running_loop()
    transport, _protocol = await loop.create_datagram_endpoint(
        lambda: SyslogDatagramProtocol(queue),
        local_addr=(settings.syslog_host, settings.syslog_port),
        family=socket.AF_INET,
    )
    logger.info("syslog receiver listening on %s:%s/udp", settings.syslog_host, settings.syslog_port)

    try:
        while True:
            batch = await _flush_batch(queue, settings.collector_batch_max_size)
            try:
                response = await ingest_collector_batch(
                    CollectorIngestBatch(logs=batch),
                    collector,
                )
                logger.info(
                    "processed syslog batch accepted=%s rejected=%s",
                    response["accepted"],
                    response["rejected"],
                )
            except Exception:
                logger.exception("failed to ingest syslog batch")
    finally:
        transport.close()


def status_payload() -> dict[str, Any]:
    return {
        "status": "enabled" if settings.syslog_enabled else "disabled",
        "host": settings.syslog_host,
        "port": settings.syslog_port,
        "transport": "udp",
        "collector_token_configured": bool(settings.syslog_collector_token),
        "checked_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AI SOC UDP syslog receiver")
    parser.add_argument("--check", action="store_true", help="validate syslog receiver configuration")
    return parser


def main() -> int:
    logging.basicConfig(level=getattr(logging, settings.log_level, logging.INFO))
    args = build_parser().parse_args()
    if args.check:
        if settings.syslog_enabled and not settings.syslog_collector_token:
            raise SystemExit("SYSLOG_COLLECTOR_TOKEN is required when SYSLOG_ENABLED=true")
        print(status_payload())
        return 0
    asyncio.run(run_syslog_receiver())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
