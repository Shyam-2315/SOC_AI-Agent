from ai.correlation_engine import correlate_events
from app.common.mongo import paginated_response
from app.common.pagination import Pagination
from app.db.client import alerts_collection


async def detect_campaigns(
    organization_id: str,
    pagination: Pagination,
) -> dict:
    query = {"organization_id": organization_id}
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
    return {
        "total_alerts": total_alerts,
        "critical_alerts": critical_alerts,
        "malware_alerts": malware_alerts,
        "ransomware_alerts": ransomware_alerts,
    }
