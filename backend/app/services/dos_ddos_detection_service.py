from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from app.core.config import settings
from app.db.client import (
    alerts_collection,
    incidents_collection,
    organizations_collection,
    response_actions_collection,
    security_detections_collection,
)
from app.realtime.events import build_realtime_event
from app.realtime.pubsub import get_redis_client, publish_realtime_event
from app.services import blocklist_service
from app.services.audit import write_audit_event


WINDOW_SECONDS = 60
DETECTION_SUPPRESSION_SECONDS = 300
AUTO_BLOCK_MINUTES = 15
_IN_MEMORY_COUNTERS: dict[str, deque[datetime]] = defaultdict(deque)
_IN_MEMORY_SETS: dict[str, dict[str, datetime]] = defaultdict(dict)
_IN_MEMORY_FLAGS: dict[str, datetime] = {}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _prune_counter(key: str, now: datetime) -> None:
    bucket = _IN_MEMORY_COUNTERS[key]
    cutoff = now - timedelta(seconds=WINDOW_SECONDS)
    while bucket and bucket[0] < cutoff:
        bucket.popleft()


def _prune_set(key: str, now: datetime) -> None:
    cutoff = now - timedelta(seconds=WINDOW_SECONDS)
    values = _IN_MEMORY_SETS[key]
    expired = [item for item, ts in values.items() if ts < cutoff]
    for item in expired:
        values.pop(item, None)


async def _incr_counter(key: str) -> int:
    now = _utcnow()
    redis_client = await get_redis_client()
    if redis_client is not None:
        value = await redis_client.incr(key)
        await redis_client.expire(key, WINDOW_SECONDS)
        return int(value)

    bucket = _IN_MEMORY_COUNTERS[key]
    bucket.append(now)
    _prune_counter(key, now)
    return len(bucket)


async def _add_unique_value(key: str, value: str) -> int:
    now = _utcnow()
    redis_client = await get_redis_client()
    if redis_client is not None:
        await redis_client.sadd(key, value)
        await redis_client.expire(key, WINDOW_SECONDS)
        return int(await redis_client.scard(key))

    values = _IN_MEMORY_SETS[key]
    values[value] = now
    _prune_set(key, now)
    return len(values)


async def _get_counter(key: str) -> int:
    now = _utcnow()
    redis_client = await get_redis_client()
    if redis_client is not None:
        value = await redis_client.get(key)
        return int(value or 0)

    _prune_counter(key, now)
    return len(_IN_MEMORY_COUNTERS[key])


async def _zadd_counter(key: str, member: str) -> None:
    redis_client = await get_redis_client()
    if redis_client is not None:
        await redis_client.zincrby(key, 1, member)
        await redis_client.expire(key, WINDOW_SECONDS)
        return

    counter_key = f"{key}:{member}"
    await _incr_counter(counter_key)


async def _top_from_key(key: str, limit: int) -> list[dict[str, Any]]:
    redis_client = await get_redis_client()
    if redis_client is not None:
        pairs = await redis_client.zrevrange(key, 0, max(limit - 1, 0), withscores=True)
        return [{"value": member, "count": int(score)} for member, score in pairs]

    prefix = f"{key}:"
    now = _utcnow()
    items = []
    for bucket_key in list(_IN_MEMORY_COUNTERS.keys()):
        if not bucket_key.startswith(prefix):
            continue
        _prune_counter(bucket_key, now)
        count = len(_IN_MEMORY_COUNTERS[bucket_key])
        if count:
            items.append({"value": bucket_key[len(prefix) :], "count": count})
    items.sort(key=lambda item: item["count"], reverse=True)
    return items[:limit]


async def _get_unique_count(path: str) -> int:
    return await _add_unique_value(f"traffic:endpoint:{path}:unique_ips", "__count_probe__")


async def _mark_detection_once(key: str, ttl_seconds: int = DETECTION_SUPPRESSION_SECONDS) -> bool:
    now = _utcnow()
    redis_client = await get_redis_client()
    if redis_client is not None:
        return bool(await redis_client.set(key, "1", ex=ttl_seconds, nx=True))

    existing = _IN_MEMORY_FLAGS.get(key)
    if existing and existing > now:
        return False
    _IN_MEMORY_FLAGS[key] = now + timedelta(seconds=ttl_seconds)
    return True


async def _clear_memory_probe(key: str) -> None:
    if key in _IN_MEMORY_SETS:
        _IN_MEMORY_SETS[key].pop("__count_probe__", None)


async def resolve_security_organization_id(preferred_org_id: str | None) -> str | None:
    if preferred_org_id:
        return preferred_org_id
    organizations = []
    cursor = organizations_collection.find({})
    async for organization in cursor:
        organizations.append(organization)
        if len(organizations) > 1:
            return None
    if len(organizations) == 1:
        return str(organizations[0]["_id"])
    return None


def _mitre_for_event(event_type: str) -> dict[str, str]:
    if event_type == "ddos_attack":
        return {
            "mitre_tactic": "Impact",
            "mitre_tactic_id": "TA0040",
            "mitre_tactic_name": "Impact",
            "mitre_technique": "T1499 - Endpoint Denial of Service",
            "mitre_technique_id": "T1499",
            "mitre_technique_name": "Endpoint Denial of Service",
        }
    return {
        "mitre_tactic": "Impact",
        "mitre_tactic_id": "TA0040",
        "mitre_tactic_name": "Impact",
        "mitre_technique": "T1498 - Network Denial of Service",
        "mitre_technique_id": "T1498",
        "mitre_technique_name": "Network Denial of Service",
    }


async def _store_detection_event(detection: dict[str, Any]) -> str:
    document = {**detection, "created_at": _utcnow()}
    result = await security_detections_collection.insert_one(document)
    return str(result.inserted_id)


async def _upsert_security_incident(
    detection: dict[str, Any],
    organization_id: str,
    alert_id: str,
) -> str | None:
    event_type = detection["event_type"]
    target_path = detection["target_path"]
    source_ip = detection["source_ip"]
    now = _utcnow()

    query = {
        "organization_id": organization_id,
        "status": {"$nin": ["resolved", "closed"]},
        "security_detection_type": event_type,
    }
    if event_type == "ddos_attack":
        query["security_target_path"] = target_path
        title = f"DDoS Activity Targeting {target_path}"
        description = f"Repeated distributed traffic was detected against {target_path}."
    else:
        query["security_source_ip"] = source_ip
        title = f"DoS Activity From {source_ip}"
        description = f"Repeated abusive traffic was detected from {source_ip}."

    incident = await incidents_collection.find_one(query)
    if incident:
        related_alert_ids = list(dict.fromkeys([*(incident.get("related_alert_ids") or []), alert_id]))
        await incidents_collection.update_one(
            {"_id": incident["_id"]},
            {
                "$set": {
                    "updated_at": now,
                    "security_target_path": target_path,
                    "security_source_ip": source_ip,
                    "related_alert_ids": related_alert_ids,
                    "investigation_summary": detection["message"],
                }
            },
        )
        return str(incident["_id"])

    incident_data = {
        "alert_id": alert_id,
        "title": title,
        "description": description,
        "severity": detection["severity"],
        "status": "new",
        "assigned_to": None,
        "assigned_to_user_id": None,
        "assigned_to_email": None,
        "investigation_notes": "",
        "investigation_summary": detection["message"],
        "mitre_tactic": detection["mitre_tactic"],
        "mitre_tactic_id": detection["mitre_tactic_id"],
        "mitre_tactic_name": detection["mitre_tactic_name"],
        "mitre_technique": detection["mitre_technique"],
        "mitre_technique_id": detection["mitre_technique_id"],
        "mitre_technique_name": detection["mitre_technique_name"],
        "organization_id": organization_id,
        "security_detection_type": event_type,
        "security_target_path": target_path,
        "security_source_ip": source_ip,
        "related_alert_ids": [alert_id],
        "timestamp": now,
    }
    result = await incidents_collection.insert_one(incident_data)
    return str(result.inserted_id)


async def _create_security_alert_artifacts(detection: dict[str, Any]) -> dict[str, Any] | None:
    organization_id = await resolve_security_organization_id(detection.get("organization_id"))
    if not organization_id:
        await _store_detection_event({**detection, "organization_id": None, "unassigned": True})
        return None

    alert_data = {
        "log_id": f"security-{uuid4()}",
        "title": detection["title"],
        "source": "traffic-monitor",
        "event_type": detection["event_type"],
        "severity": detection["severity"],
        "message": detection["message"],
        "ip_address": detection["source_ip"],
        "organization_id": organization_id,
        "threat_score": detection["threat_score"],
        "threat_label": "suspicious",
        "status": "open",
        "target_path": detection["target_path"],
        "evidence": detection["evidence"],
        "ip_reputation": "unknown",
        "timestamp": _utcnow(),
        **_mitre_for_event(detection["event_type"]),
    }
    alert_result = await alerts_collection.insert_one(alert_data)
    alert_id = str(alert_result.inserted_id)
    incident_id = await _upsert_security_incident(detection | alert_data, organization_id, alert_id)

    auto_block = detection.get("auto_block", False)
    action_text = (
        f"Blocked malicious IP: {detection['source_ip']}"
        if auto_block
        else f"Recommended block for suspicious IP: {detection['source_ip']}"
    )
    response_action_data = {
        "alert_id": alert_id,
        "incident_id": incident_id,
        "organization_id": organization_id,
        "event_type": detection["event_type"],
        "severity": detection["severity"],
        "ip_address": detection["source_ip"],
        "action_type": "block_ip",
        "reason": detection["reason"],
        "target_path": detection["target_path"],
        "automated_actions": [action_text],
        "blocked_ips": [detection["source_ip"]] if auto_block else [],
        "status": "simulated" if auto_block else "pending",
        "timestamp": _utcnow(),
    }
    response_action_result = await response_actions_collection.insert_one(response_action_data)
    detection_id = await _store_detection_event(
        {
            **detection,
            "organization_id": organization_id,
            "alert_id": alert_id,
            "incident_id": incident_id,
            "response_action_id": str(response_action_result.inserted_id),
        }
    )

    await write_audit_event(
        event_type=f"security.{detection['event_type']}.detected",
        organization_id=organization_id,
        target_type="security_detection",
        target_id=detection_id,
        metadata={"source_ip": detection["source_ip"], "target_path": detection["target_path"]},
    )

    alert_event = build_realtime_event(
        event_type="soc.alert.created",
        organization_id=organization_id,
        payload={
            "alert_id": alert_id,
            "event_type": alert_data["event_type"],
            "severity": alert_data["severity"],
            "message": alert_data["message"],
            "title": alert_data["title"],
            "ip_address": alert_data["ip_address"],
            "target_path": alert_data["target_path"],
            "mitre_tactic": alert_data["mitre_tactic"],
            "mitre_technique": alert_data["mitre_technique"],
            "mitre_tactic_id": alert_data["mitre_tactic_id"],
            "mitre_tactic_name": alert_data["mitre_tactic_name"],
            "mitre_technique_id": alert_data["mitre_technique_id"],
            "mitre_technique_name": alert_data["mitre_technique_name"],
            "threat_score": alert_data["threat_score"],
            "evidence": alert_data["evidence"],
            "timestamp": alert_data["timestamp"],
        },
    )
    await publish_realtime_event(alert_event)

    if incident_id is not None:
        incident_event = build_realtime_event(
            event_type="soc.incident.created",
            organization_id=organization_id,
            payload={
                "incident_id": incident_id,
                "alert_id": alert_id,
                "title": (
                    f"DDoS Activity Targeting {detection['target_path']}"
                    if detection["event_type"] == "ddos_attack"
                    else f"DoS Activity From {detection['source_ip']}"
                ),
                "severity": detection["severity"],
                "status": "new",
                "timestamp": _utcnow(),
                "mitre_tactic_id": alert_data["mitre_tactic_id"],
                "mitre_tactic_name": alert_data["mitre_tactic_name"],
                "mitre_technique_id": alert_data["mitre_technique_id"],
                "mitre_technique_name": alert_data["mitre_technique_name"],
            },
        )
        await publish_realtime_event(incident_event)

    action_event = build_realtime_event(
        event_type="soc.response_action.created",
        organization_id=organization_id,
        payload={
            "response_action_id": str(response_action_result.inserted_id),
            "alert_id": alert_id,
            "incident_id": incident_id,
            "event_type": detection["event_type"],
            "severity": detection["severity"],
            "ip_address": detection["source_ip"],
            "automated_actions": response_action_data["automated_actions"],
            "blocked_ips": response_action_data["blocked_ips"],
            "status": response_action_data["status"],
            "timestamp": response_action_data["timestamp"],
        },
    )
    await publish_realtime_event(action_event)
    return {
        "organization_id": organization_id,
        "alert_id": alert_id,
        "incident_id": incident_id,
        "response_action_id": str(response_action_result.inserted_id),
    }


def _dos_detection(
    *,
    source_ip: str,
    target_path: str,
    request_count: int,
    error_count: int,
    organization_id: str | None,
) -> dict[str, Any] | None:
    if (
        request_count < settings.dos_ip_requests_per_minute
        and error_count < settings.dos_ip_errors_per_minute
    ):
        return None

    reason = (
        "High error-rate abuse detected"
        if error_count >= settings.dos_ip_errors_per_minute
        else "Request threshold exceeded from a single IP"
    )
    return {
        "detection_type": "dos",
        "event_type": "dos_attack",
        "title": "Possible DoS Attack Detected",
        "severity": "critical" if error_count >= settings.dos_ip_errors_per_minute else "high",
        "source_ip": source_ip,
        "target_path": target_path,
        "organization_id": organization_id,
        "message": (
            f"Possible DoS activity from {source_ip} against {target_path}; "
            f"requests={request_count}; errors={error_count}; window=1m"
        ),
        "reason": reason,
        "threat_score": 92 if error_count >= settings.dos_ip_errors_per_minute else 84,
        "evidence": {
            "request_count": request_count,
            "error_count": error_count,
            "unique_ip_count": 1,
            "time_window": "1m",
            "endpoint": target_path,
        },
        "auto_block": settings.auto_block_dos_ips,
    }


def _ddos_detection(
    *,
    source_ip: str,
    target_path: str,
    endpoint_requests: int,
    unique_ips: int,
    organization_id: str | None,
) -> dict[str, Any] | None:
    if unique_ips >= settings.ddos_endpoint_unique_ips_per_minute:
        severity = "critical"
    elif endpoint_requests >= settings.ddos_endpoint_requests_per_minute and unique_ips >= 2:
        severity = "high"
    else:
        return None

    return {
        "detection_type": "ddos",
        "event_type": "ddos_attack",
        "title": "Possible DDoS Attack Detected",
        "severity": severity,
        "source_ip": source_ip,
        "target_path": target_path,
        "organization_id": organization_id,
        "message": (
            f"Possible DDoS activity targeting {target_path}; "
            f"requests={endpoint_requests}; unique_ips={unique_ips}; window=1m"
        ),
        "reason": "Multiple IPs are attacking the same endpoint",
        "threat_score": 96 if severity == "critical" else 88,
        "evidence": {
            "request_count": endpoint_requests,
            "error_count": 0,
            "unique_ip_count": unique_ips,
            "time_window": "1m",
            "endpoint": target_path,
        },
        "auto_block": False,
    }


async def process_traffic_event(
    *,
    source_ip: str,
    path: str,
    method: str,
    status_code: int,
    user_agent: str | None,
    organization_id: str | None,
    timestamp: datetime | None = None,
) -> dict[str, Any]:
    _ = method
    _ = user_agent
    _ = timestamp
    path_key = path or "/"
    request_count = await _incr_counter(f"traffic:ip:{source_ip}:1m")
    endpoint_requests = await _incr_counter(f"traffic:endpoint:{path_key}:1m")
    unique_ips = await _add_unique_value(f"traffic:endpoint:{path_key}:unique_ips", source_ip)
    if await get_redis_client() is None:
        await _clear_memory_probe(f"traffic:endpoint:{path_key}:unique_ips")
    if status_code >= 400:
        error_count = await _incr_counter(f"traffic:ip:{source_ip}:errors:1m")
    else:
        error_count = await _get_counter(f"traffic:ip:{source_ip}:errors:1m")
    await _zadd_counter("traffic:top_ips:1m", source_ip)
    await _zadd_counter("traffic:top_endpoints:1m", path_key)
    total_requests = await _incr_counter("traffic:requests:1m")

    detections = []
    dos = _dos_detection(
        source_ip=source_ip,
        target_path=path_key,
        request_count=request_count,
        error_count=error_count,
        organization_id=organization_id,
    )
    if dos and await _mark_detection_once(f"traffic:detection:dos:{source_ip}"):
        if dos["auto_block"]:
            await blocklist_service.block_ip(
                source_ip,
                dos["reason"],
                AUTO_BLOCK_MINUTES,
                organization_id=organization_id,
                blocked_by="auto-dos-protection",
            )
        dos["artifacts"] = await _create_security_alert_artifacts(dos)
        detections.append(dos)

    ddos = _ddos_detection(
        source_ip=source_ip,
        target_path=path_key,
        endpoint_requests=endpoint_requests,
        unique_ips=unique_ips,
        organization_id=organization_id,
    )
    if ddos and await _mark_detection_once(f"traffic:detection:ddos:{path_key}"):
        ddos["artifacts"] = await _create_security_alert_artifacts(ddos)
        detections.append(ddos)

    return {
        "total_requests": total_requests,
        "request_count": request_count,
        "endpoint_requests": endpoint_requests,
        "unique_ips": unique_ips,
        "error_count": error_count,
        "detections": detections,
    }


async def get_security_summary(organization_id: str) -> dict[str, Any]:
    total_requests = await _get_counter("traffic:requests:1m")
    top_source_ips = await _top_from_key("traffic:top_ips:1m", 10)
    top_endpoints = await _top_from_key("traffic:top_endpoints:1m", 10)

    detections = []
    cursor = security_detections_collection.find({"organization_id": organization_id}).sort(
        "created_at", -1
    ).limit(50)
    async for document in cursor:
        detections.append(
            {
                "id": str(document["_id"]),
                "detection_type": document.get("detection_type"),
                "event_type": document.get("event_type"),
                "title": document.get("title"),
                "severity": document.get("severity"),
                "source_ip": document.get("source_ip"),
                "target_path": document.get("target_path"),
                "reason": document.get("reason"),
                "evidence": document.get("evidence"),
                "created_at": document.get("created_at"),
                "auto_block": document.get("auto_block", False),
                "alert_id": document.get("alert_id"),
                "incident_id": document.get("incident_id"),
            }
        )

    dos_detections = [item for item in detections if item["detection_type"] == "dos"]
    ddos_detections = [item for item in detections if item["detection_type"] == "ddos"]
    return {
        "requests_per_minute": total_requests,
        "top_source_ips": top_source_ips,
        "targeted_endpoints": top_endpoints,
        "possible_dos_detections": dos_detections,
        "possible_ddos_detections": ddos_detections,
        "recent_detections": detections,
        "auto_block_enabled": settings.auto_block_dos_ips,
        "thresholds": {
            "dos_ip_requests_per_minute": settings.dos_ip_requests_per_minute,
            "dos_ip_errors_per_minute": settings.dos_ip_errors_per_minute,
            "ddos_endpoint_requests_per_minute": settings.ddos_endpoint_requests_per_minute,
            "ddos_endpoint_unique_ips_per_minute": settings.ddos_endpoint_unique_ips_per_minute,
        },
    }

