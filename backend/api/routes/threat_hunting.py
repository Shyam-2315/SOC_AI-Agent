from fastapi import APIRouter, Depends

from ai.correlation_engine import correlate_events
from core.database import alerts_collection
from core.dependencies import Pagination, get_current_user, pagination_params


router = APIRouter(
    prefix="/threat-hunting",
    tags=["Threat Hunting"],
)


@router.get("/campaigns")
async def detect_campaigns(
    pagination: Pagination = Depends(pagination_params),
    user=Depends(get_current_user),
):
    query = {
        "organization_id": user["organization_id"],
    }

    alerts = []
    cursor = (
        alerts_collection.find(query)
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


@router.get("/timeline")
async def attack_timeline(
    pagination: Pagination = Depends(pagination_params),
    user=Depends(get_current_user),
):
    query = {
        "organization_id": user["organization_id"],
    }

    timeline = []
    cursor = (
        alerts_collection.find(query)
        .sort("timestamp", -1)
        .skip(pagination.offset)
        .limit(pagination.limit)
    )

    async for alert in cursor:
        timeline.append({
            "event_type": alert.get("event_type"),
            "severity": alert.get("severity"),
            "source": alert.get("source"),
            "ip_address": alert.get("ip_address"),
            "timestamp": alert.get("timestamp"),
        })

    total = await alerts_collection.count_documents(query)

    return {
        "items": timeline,
        "total": total,
        "limit": pagination.limit,
        "offset": pagination.offset,
    }


@router.get("/statistics")
async def threat_statistics(
    user=Depends(get_current_user),
):
    organization_query = {
        "organization_id": user["organization_id"],
    }

    total_alerts = await alerts_collection.count_documents(organization_query)
    critical_alerts = await alerts_collection.count_documents({
        **organization_query,
        "severity": {
            "$regex": "^critical$",
            "$options": "i",
        },
    })
    malware_alerts = await alerts_collection.count_documents({
        **organization_query,
        "event_type": "malware",
    })
    ransomware_alerts = await alerts_collection.count_documents({
        **organization_query,
        "event_type": "ransomware",
    })

    return {
        "total_alerts": total_alerts,
        "critical_alerts": critical_alerts,
        "malware_alerts": malware_alerts,
        "ransomware_alerts": ransomware_alerts,
    }
