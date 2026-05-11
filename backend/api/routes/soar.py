from fastapi import APIRouter, Depends

from core.database import response_actions_collection
from core.dependencies import Pagination, get_current_user, pagination_params


router = APIRouter(
    prefix="/soar",
    tags=["SOAR"],
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


@router.get("/actions")
async def get_response_actions(
    pagination: Pagination = Depends(pagination_params),
    user=Depends(get_current_user),
):
    query = {
        "organization_id": user["organization_id"],
    }

    actions = []
    cursor = (
        response_actions_collection.find(query)
        .sort("timestamp", -1)
        .skip(pagination.offset)
        .limit(pagination.limit)
    )

    async for action in cursor:
        action["_id"] = str(action["_id"])
        actions.append(action)

    total = await response_actions_collection.count_documents(query)

    return {
        "items": actions,
        "total": total,
        "limit": pagination.limit,
        "offset": pagination.offset,
    }


@router.get("/blocked-ips")
async def get_blocked_ips(
    user=Depends(get_current_user),
):
    blocked_ips = await response_actions_collection.distinct(
        "ip_address",
        {
            "organization_id": user["organization_id"],
            "automated_actions": {
                "$regex": "^Blocked malicious IP:",
            },
        },
    )

    return {
        "blocked_ips": blocked_ips,
    }


@router.get("/playbook/{event_type}")
async def get_playbook(
    event_type: str,
    user=Depends(get_current_user),
):
    return {
        "event_type": event_type,
        "playbook": PLAYBOOKS.get(event_type, ["No playbook available"]),
    }
