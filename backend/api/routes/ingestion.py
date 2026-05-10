from fastapi import APIRouter

from schemas.log_schema import LogEvent

from core.database import (
    logs_collection,
    alerts_collection
)

from services.ai.threat_engine import classify_threat

router = APIRouter()


@router.post("/ingest")
async def ingest_log(log: LogEvent):

    log_dict = log.dict()

    threat_result = classify_threat(
        log.event_type,
        log.message
    )

    alert = {
        **log_dict,
        **threat_result
    }

    await logs_collection.insert_one(log_dict)

    result = await alerts_collection.insert_one(alert)

    alert["_id"] = str(result.inserted_id)

    return {
        "status": "processed",
        "alert": alert
    }


@router.get("/alerts")
async def get_alerts():

    alerts = []

    async for alert in alerts_collection.find():

        alert["_id"] = str(alert["_id"])

        alerts.append(alert)

    return alerts