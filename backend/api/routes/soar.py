from fastapi import APIRouter, Depends

from core.dependencies import (
    get_current_user
)

from ai.response_engine import (
    BLOCKED_IPS
)


router = APIRouter(
    prefix="/soar",
    tags=["SOAR"]
)


@router.get("/blocked-ips")
async def get_blocked_ips(
    user=Depends(get_current_user)
):

    return {
        "blocked_ips": BLOCKED_IPS
    }


@router.get("/playbook/{event_type}")
async def get_playbook(
    event_type: str,
    user=Depends(get_current_user)
):

    playbooks = {

        "ssh_attack": [
            "Investigate source IP",
            "Check failed login attempts",
            "Enable MFA",
            "Block malicious IP"
        ],

        "malware": [
            "Isolate endpoint",
            "Run malware scan",
            "Collect forensic evidence",
            "Remove malicious files"
        ],

        "ransomware": [
            "Disconnect infected systems",
            "Check backup availability",
            "Notify incident response team",
            "Start recovery procedures"
        ]
    }

    return {
        "event_type": event_type,
        "playbook": playbooks.get(
            event_type,
            ["No playbook available"]
        )
    }