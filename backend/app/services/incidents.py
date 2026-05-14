from datetime import datetime, timezone

from fastapi import HTTPException

from app.common.mongo import paginated_response, parse_object_id, serialize_document
from app.common.pagination import Pagination
from app.db.client import (
    alerts_collection,
    correlated_incidents_collection,
    incidents_collection,
    response_actions_collection,
)
from app.schemas.incident import IncidentCreate, IncidentUpdate
from app.realtime.events import build_realtime_event
from app.realtime.pubsub import publish_realtime_event
from app.services.audit import write_audit_event
from app.services.investigation_summary import generate_investigation_summary


async def create_incident(
    incident: IncidentCreate,
    user: dict,
) -> dict:
    incident_data = {
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "assigned_to": incident.assigned_to,
        "assigned_to_user_id": incident.assigned_to_user_id,
        "assigned_to_email": incident.assigned_to_email or incident.assigned_to,
        "investigation_notes": incident.investigation_notes or "",
        "status": "new",
        "created_by": user["email"],
        "organization_id": user["organization_id"],
        "timestamp": datetime.now(timezone.utc),
    }
    result = await incidents_collection.insert_one(incident_data)
    incident_data["_id"] = result.inserted_id
    await write_audit_event(
        event_type="incident.created",
        actor=user,
        target_type="incident",
        target_id=str(result.inserted_id),
        metadata={"severity": incident.severity},
    )
    return {
        "message": "Incident created",
        "incident": serialize_document(incident_data),
    }


async def list_incidents(
    organization_id: str,
    pagination: Pagination,
) -> dict:
    query = {"organization_id": organization_id}
    items = []
    cursor = (
        incidents_collection.find(query)
        .sort("timestamp", -1)
        .skip(pagination.offset)
        .limit(pagination.limit)
    )
    async for incident in cursor:
        items.append(serialize_document(incident))

    total = await incidents_collection.count_documents(query)
    return paginated_response(items, total, pagination)


async def update_incident_status(
    incident_id: str,
    update: IncidentUpdate,
    user: dict,
) -> dict:
    object_id = parse_object_id(incident_id, "incident")
    update_data = update.model_dump(exclude_unset=True)
    if "assigned_to_email" in update_data:
        update_data["assigned_to"] = update_data["assigned_to_email"]
    if not update_data:
        raise HTTPException(status_code=400, detail="No updates provided")
    update_data["updated_at"] = datetime.now(timezone.utc)
    update_data["updated_by"] = user["email"]
    result = await incidents_collection.update_one(
        {
            "_id": object_id,
            "organization_id": user["organization_id"],
        },
        {"$set": update_data},
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Incident not found")
    await write_audit_event(
        event_type="incident.status_updated",
        actor=user,
        target_type="incident",
        target_id=incident_id,
        metadata={"fields": sorted(update_data.keys()), "status": update_data.get("status")},
    )
    incident_detail = await get_incident(incident_id, user["organization_id"])
    await publish_realtime_event(
        build_realtime_event(
            event_type="incident.updated",
            organization_id=user["organization_id"],
            payload={
                "incident_id": incident_id,
                "status": incident_detail.get("status"),
                "assigned_to_email": incident_detail.get("assigned_to_email"),
                "updated_at": incident_detail.get("updated_at"),
            },
        )
    )
    return {"message": "Incident updated", "incident": incident_detail}


async def _list_alerts_by_ids(organization_id: str, alert_ids: list[str]) -> list[dict]:
    if not alert_ids:
        return []
    cursor = alerts_collection.find({"organization_id": organization_id}).sort("timestamp", -1)
    wanted = set(alert_ids)
    alerts = []
    async for alert in cursor:
        serialized = serialize_document(alert)
        if str(serialized.get("_id") or serialized.get("id")) in wanted:
            alerts.append(serialized)
    return alerts


async def _related_alert_ids(incident: dict, organization_id: str) -> tuple[list[str], dict | None]:
    ids = []
    if incident.get("alert_id"):
        ids.append(str(incident["alert_id"]))
    ids.extend(str(alert_id) for alert_id in incident.get("related_alert_ids", []))

    group = None
    correlation_id = incident.get("correlation_id")
    if correlation_id:
        group = await correlated_incidents_collection.find_one(
            {"organization_id": organization_id, "correlation_id": correlation_id}
        )
    if group is None:
        group = await correlated_incidents_collection.find_one(
            {"organization_id": organization_id, "incident_id": str(incident.get("_id"))}
        )
    if group:
        ids.extend(str(alert_id) for alert_id in group.get("related_alert_ids", []))

    return list(dict.fromkeys(ids)), group


async def get_incident(incident_id: str, organization_id: str) -> dict:
    object_id = parse_object_id(incident_id, "incident")
    incident = await incidents_collection.find_one(
        {"_id": object_id, "organization_id": organization_id}
    )
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    alert_ids, group = await _related_alert_ids(incident, organization_id)
    related_alerts = await _list_alerts_by_ids(organization_id, alert_ids)
    response_actions = []
    for alert_id in alert_ids:
        cursor = response_actions_collection.find(
            {"organization_id": organization_id, "alert_id": alert_id}
        ).sort("timestamp", -1)
        async for action in cursor:
            response_actions.append(serialize_document(action))

    hosts = sorted(
        {
            str(alert.get("hostname") or alert.get("host") or alert.get("source"))
            for alert in related_alerts
            if alert.get("hostname") or alert.get("host") or alert.get("source")
        }
    )
    ips = sorted(
        {str(alert.get("ip_address")) for alert in related_alerts if alert.get("ip_address")}
    )
    mitre = []
    seen = set()
    for alert in related_alerts:
        key = (
            alert.get("mitre_tactic_id"),
            alert.get("mitre_tactic_name") or alert.get("mitre_tactic"),
            alert.get("mitre_technique_id"),
            alert.get("mitre_technique_name") or alert.get("mitre_technique"),
        )
        if key in seen:
            continue
        seen.add(key)
        mitre.append(
            {
                "tactic_id": key[0],
                "tactic_name": key[1],
                "technique_id": key[2],
                "technique_name": key[3],
            }
        )

    serialized = serialize_document(incident)
    first_mitre = mitre[0] if mitre else {}
    correlation = serialize_document(group) if group else None
    timeline_events = [
        {
            "alert_id": str(alert.get("_id") or alert.get("id")),
            "timestamp": alert.get("timestamp"),
            "event_type": alert.get("event_type"),
            "message": alert.get("message"),
            "severity": alert.get("severity"),
            "source": alert.get("source"),
            "ip_address": alert.get("ip_address"),
            "host": alert.get("hostname") or alert.get("host") or alert.get("source"),
            "attack_stage": serialized.get("attack_stage")
            or (correlation or {}).get("attack_stage"),
            "mitre": {
                "tactic_id": alert.get("mitre_tactic_id"),
                "tactic_name": alert.get("mitre_tactic_name") or alert.get("mitre_tactic"),
                "technique_id": alert.get("mitre_technique_id"),
                "technique_name": alert.get("mitre_technique_name") or alert.get("mitre_technique"),
                "subtechnique_id": alert.get("mitre_subtechnique_id"),
                "subtechnique_name": alert.get("mitre_subtechnique_name"),
            },
        }
        for alert in sorted(
            related_alerts,
            key=lambda item: str(item.get("timestamp") or ""),
            reverse=True,
        )
    ]
    serialized["related_alerts"] = related_alerts
    serialized["related_hosts"] = hosts
    serialized["related_ips"] = ips
    serialized["mitre_mappings"] = mitre
    serialized["mitre_tactic_id"] = serialized.get("mitre_tactic_id") or first_mitre.get(
        "tactic_id"
    )
    serialized["mitre_tactic_name"] = serialized.get("mitre_tactic_name") or first_mitre.get(
        "tactic_name"
    )
    serialized["mitre_technique_id"] = serialized.get("mitre_technique_id") or first_mitre.get(
        "technique_id"
    )
    serialized["mitre_technique_name"] = serialized.get(
        "mitre_technique_name"
    ) or first_mitre.get("technique_name")
    serialized["soar_actions"] = response_actions
    serialized["correlation"] = correlation
    serialized["correlation_score"] = serialized.get("correlation_score") or (correlation or {}).get(
        "correlation_score"
    )
    serialized["timeline_events"] = timeline_events
    serialized["notes"] = serialized.get("investigation_notes") or ""
    serialized["investigation_summary"] = (
        serialized.get("investigation_summary")
        or (group or {}).get("summary")
        or generate_investigation_summary(related_alerts)
    )
    return serialized
