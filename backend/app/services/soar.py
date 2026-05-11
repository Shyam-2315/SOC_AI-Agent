from app.common.mongo import paginated_response, serialize_document
from app.common.pagination import Pagination
from app.db.client import response_actions_collection


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
) -> dict:
    query = {"organization_id": organization_id}
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
