from ai.correlation_engine import correlate_events
from app.common.mongo import paginated_response
from app.common.pagination import Pagination
from app.common.mongo import parse_object_id, serialize_document
from app.db.client import alerts_collection, correlated_incidents_collection, incidents_collection
from app.services.investigation_summary import generate_investigation_summary


async def detect_campaigns(
    organization_id: str,
    pagination: Pagination,
) -> dict:
    groups = []
    cursor = (
        correlated_incidents_collection.find({"organization_id": organization_id})
        .sort("updated_at", -1)
        .skip(pagination.offset)
        .limit(pagination.limit)
    )
    async for group in cursor:
        groups.append(serialize_document(group))
    if groups:
        campaigns = groups
    else:
        alerts = []
        cursor = (
            alerts_collection.find({"organization_id": organization_id})
            .sort("timestamp", -1)
            .skip(pagination.offset)
            .limit(pagination.limit)
        )
        async for alert in cursor:
            alert["_id"] = str(alert["_id"])
            alerts.append(alert)
        campaigns = correlate_events(alerts)
    return {
        "detected_campaigns": campaigns,
        "limit": pagination.limit,
        "offset": pagination.offset,
    }


async def attack_timeline(
    organization_id: str,
    pagination: Pagination,
) -> dict:
    query = {"organization_id": organization_id}
    items = []
    cursor = (
        alerts_collection.find(query)
        .sort("timestamp", -1)
        .skip(pagination.offset)
        .limit(pagination.limit)
    )
    async for alert in cursor:
        items.append(
            {
                "event_type": alert.get("event_type"),
                "severity": alert.get("severity"),
                "source": alert.get("source"),
                "ip_address": alert.get("ip_address"),
                "mitre_tactic_id": alert.get("mitre_tactic_id"),
                "mitre_tactic_name": alert.get("mitre_tactic_name") or alert.get("mitre_tactic"),
                "mitre_technique_id": alert.get("mitre_technique_id"),
                "mitre_technique_name": alert.get("mitre_technique_name") or alert.get("mitre_technique"),
                "attack_stage": alert.get("attack_stage"),
                "timestamp": alert.get("timestamp"),
            }
        )

    total = await alerts_collection.count_documents(query)
    return paginated_response(items, total, pagination)


async def threat_statistics(organization_id: str) -> dict:
    organization_query = {"organization_id": organization_id}
    total_alerts = await alerts_collection.count_documents(organization_query)
    critical_alerts = await alerts_collection.count_documents(
        {
            **organization_query,
            "severity": {
                "$regex": "^critical$",
                "$options": "i",
            },
        }
    )
    malware_alerts = await alerts_collection.count_documents(
        {
            **organization_query,
            "event_type": "malware",
        }
    )
    ransomware_alerts = await alerts_collection.count_documents(
        {
            **organization_query,
            "event_type": "ransomware",
        }
    )
    tactic_breakdown = {}
    technique_breakdown = {}
    host_breakdown = {}
    severity_distribution = {}
    cursor = alerts_collection.find(organization_query).sort("timestamp", -1).limit(500)
    async for alert in cursor:
        tactic = alert.get("mitre_tactic_name") or alert.get("mitre_tactic") or "Unknown"
        technique = alert.get("mitre_technique_id") or alert.get("mitre_technique") or "Unknown"
        host = alert.get("hostname") or alert.get("host") or alert.get("source") or "Unknown"
        severity = str(alert.get("severity") or "info").lower()
        tactic_breakdown[tactic] = tactic_breakdown.get(tactic, 0) + 1
        technique_breakdown[technique] = technique_breakdown.get(technique, 0) + 1
        host_breakdown[host] = host_breakdown.get(host, 0) + 1
        severity_distribution[severity] = severity_distribution.get(severity, 0) + 1

    recent_attack_chains = []
    group_cursor = (
        correlated_incidents_collection.find(organization_query)
        .sort("updated_at", -1)
        .limit(5)
    )
    async for group in group_cursor:
        recent_attack_chains.append(serialize_document(group))

    return {
        "total_alerts": total_alerts,
        "critical_alerts": critical_alerts,
        "malware_alerts": malware_alerts,
        "ransomware_alerts": ransomware_alerts,
        "mitre_tactic_breakdown": tactic_breakdown,
        "top_attacked_hosts": host_breakdown,
        "top_attack_techniques": technique_breakdown,
        "attack_severity_distribution": severity_distribution,
        "recent_attack_chains": recent_attack_chains,
    }


async def incident_timeline(incident_id: str, organization_id: str) -> dict:
    object_id = parse_object_id(incident_id, "incident")
    incident = await incidents_collection.find_one(
        {"_id": object_id, "organization_id": organization_id}
    )
    if not incident:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Incident not found")

    related_ids = []
    if incident.get("alert_id"):
        related_ids.append(str(incident["alert_id"]))
    related_ids.extend(str(alert_id) for alert_id in incident.get("related_alert_ids", []))

    group = None
    if incident.get("correlation_id"):
        group = await correlated_incidents_collection.find_one(
            {"organization_id": organization_id, "correlation_id": incident["correlation_id"]}
        )
    if group is None:
        group = await correlated_incidents_collection.find_one(
            {"organization_id": organization_id, "incident_id": incident_id}
        )
    if group:
        related_ids.extend(str(alert_id) for alert_id in group.get("related_alert_ids", []))
    related_ids = list(dict.fromkeys(related_ids))

    alerts = []
    wanted = set(related_ids)
    cursor = alerts_collection.find({"organization_id": organization_id}).sort("timestamp", -1)
    async for alert in cursor:
        serialized = serialize_document(alert)
        if str(serialized.get("_id") or serialized.get("id")) in wanted:
            alerts.append(serialized)

    events = []
    for alert in sorted(alerts, key=lambda item: str(item.get("timestamp") or ""), reverse=True):
        events.append(
            {
                "alert_id": str(alert.get("_id") or alert.get("id")),
                "timestamp": alert.get("timestamp"),
                "event_type": alert.get("event_type"),
                "message": alert.get("message"),
                "severity": alert.get("severity"),
                "source": alert.get("source"),
                "ip_address": alert.get("ip_address"),
                "host": alert.get("hostname") or alert.get("host") or alert.get("source"),
                "attack_stage": (group or {}).get("attack_stage"),
                "mitre": {
                    "tactic_id": alert.get("mitre_tactic_id"),
                    "tactic_name": alert.get("mitre_tactic_name") or alert.get("mitre_tactic"),
                    "technique_id": alert.get("mitre_technique_id"),
                    "technique_name": alert.get("mitre_technique_name") or alert.get("mitre_technique"),
                    "subtechnique_id": alert.get("mitre_subtechnique_id"),
                    "subtechnique_name": alert.get("mitre_subtechnique_name"),
                },
            }
        )

    return {
        "incident_id": incident_id,
        "summary": incident.get("investigation_summary")
        or (group or {}).get("summary")
        or generate_investigation_summary(alerts),
        "correlation": serialize_document(group) if group else None,
        "correlated_hosts": sorted(
            {event["host"] for event in events if event.get("host")}
        ),
        "correlated_ips": sorted(
            {event["ip_address"] for event in events if event.get("ip_address")}
        ),
        "events": events,
    }
