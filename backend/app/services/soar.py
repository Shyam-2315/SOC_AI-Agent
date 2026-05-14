from fastapi import HTTPException

from app.common.mongo import paginated_response, parse_object_id, serialize_document
from app.common.pagination import Pagination
from app.db.client import (
    correlated_incidents_collection,
    incidents_collection,
    response_actions_collection,
)


PLAYBOOKS = {
    "ssh_attack": [
        "Investigate source IP",
        "Check failed login attempts",
        "Enable MFA",
        "Block malicious IP",
    ],
    "malware": [
        "Isolate endpoint",
        "Run malware scan",
        "Collect forensic evidence",
        "Remove malicious files",
    ],
    "ransomware": [
        "Disconnect infected systems",
        "Check backup availability",
        "Notify incident response team",
        "Start recovery procedures",
    ],
    "network_activity": [
        "Inspect network traffic",
        "Review outbound connections",
        "Block suspicious destinations",
    ],
}


async def list_response_actions(
    organization_id: str,
    pagination: Pagination,
    incident_id: str | None = None,
) -> dict:
    query = {"organization_id": organization_id}
    if incident_id:
        object_id = parse_object_id(incident_id, "incident")
        incident = await incidents_collection.find_one(
            {"_id": object_id, "organization_id": organization_id}
        )
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        alert_ids = []
        if incident.get("alert_id"):
            alert_ids.append(str(incident["alert_id"]))
        alert_ids.extend(str(alert_id) for alert_id in incident.get("related_alert_ids", []))

        group = None
        if incident.get("correlation_id"):
            group = await correlated_incidents_collection.find_one(
                {
                    "organization_id": organization_id,
                    "correlation_id": incident["correlation_id"],
                }
            )
        if group is None:
            group = await correlated_incidents_collection.find_one(
                {"organization_id": organization_id, "incident_id": incident_id}
            )
        if group:
            alert_ids.extend(str(alert_id) for alert_id in group.get("related_alert_ids", []))
        alert_ids = list(dict.fromkeys(alert_ids))
        query["$or"] = [{"incident_id": incident_id}, {"alert_id": {"$in": alert_ids}}]

    items = []
    cursor = (
        response_actions_collection.find(query)
        .sort("timestamp", -1)
        .skip(pagination.offset)
        .limit(pagination.limit)
    )
    async for action in cursor:
        items.append(serialize_document(action))

    total = await response_actions_collection.count_documents(query)
    return paginated_response(items, total, pagination)


async def list_blocked_ips(organization_id: str) -> dict:
    blocked_ips = await response_actions_collection.distinct(
        "ip_address",
        {
            "organization_id": organization_id,
            "automated_actions": {
                "$regex": "^Blocked malicious IP:",
            },
        },
    )
    return {"blocked_ips": blocked_ips}


def get_playbook(event_type: str) -> dict:
    return {
        "event_type": event_type,
        "playbook": PLAYBOOKS.get(event_type, ["No playbook available"]),
    }
