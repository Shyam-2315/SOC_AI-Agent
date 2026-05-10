from fastapi import APIRouter, Depends

from pydantic import BaseModel

from core.database import (
    logs_collection,
    alerts_collection
)

from core.dependencies import (
    get_current_user
)

from websocket.manager import manager

from ai.anomaly_detector import detect_anomaly
from ai.threat_intel import check_ip_reputation
from ai.mitre_mapper import map_to_mitre
from ai.response_engine import generate_response


router = APIRouter(
    tags=["Ingestion"]
)


class LogIngest(BaseModel):

    source: str
    event_type: str
    message: str
    ip_address: str
    event_count: int


def classify_threat(event_type: str):

    high_threats = [
        "ssh_attack",
        "malware",
        "ransomware"
    ]

    if event_type in high_threats:

        return "High"

    return "Low"


@router.post("/ingest")
async def ingest_log(
    log: LogIngest,
    user=Depends(get_current_user)
):

    log_dict = log.dict()

    anomaly_result = detect_anomaly(
        log.event_count
    )

    reputation_result = check_ip_reputation(
        log.ip_address
    )

    mitre_result = map_to_mitre(
        log.event_type
    )

    threat_level = classify_threat(
        log.event_type
    )

    # AI anomaly escalation
    if anomaly_result["is_anomaly"]:

        threat_level = "Critical"

    # Threat intelligence escalation
    if reputation_result["malicious"]:

        threat_level = "Critical"

    alert_data = {

        "source": log.source,

        "event_type": log.event_type,

        "message": log.message,

        "ip_address": log.ip_address,

        "event_count": log.event_count,

        "severity": threat_level,

        # AI anomaly
        "anomaly_detected":
            anomaly_result["is_anomaly"],

        "anomaly_score":
            anomaly_result["anomaly_score"],

        # Threat Intel
        "malicious_ip":
            reputation_result["malicious"],

        "threat_source":
            reputation_result["threat_source"],

        "threat_confidence":
            reputation_result["confidence"],

        # MITRE ATT&CK
        "mitre_technique_id":
            mitre_result["technique_id"],

        "mitre_technique":
            mitre_result["technique_name"],

        "mitre_tactic":
            mitre_result["tactic"]
    }

    # SOAR RESPONSE ENGINE
    response_actions = generate_response(
        alert_data
    )

    alert_data["automated_actions"] = (
        response_actions["automated_actions"]
    )

    log_result = await logs_collection.insert_one(
        log_dict
    )

    alert_result = await alerts_collection.insert_one(
        alert_data
    )

    alert_data["_id"] = str(
        alert_result.inserted_id
    )

    # REAL-TIME ALERT STREAM
    await manager.broadcast({
        "type": "new_alert",
        "data": alert_data
    })

    # REAL-TIME SOAR STREAM
    await manager.broadcast({
        "type": "automated_response",
        "data": response_actions
    })

    return {
        "status": "processed",
        "log_id": str(log_result.inserted_id),
        "alert": alert_data,
        "response_actions": response_actions
    }


@router.get("/alerts")
async def get_alerts(
    user=Depends(get_current_user)
):

    alerts = []

    async for alert in alerts_collection.find():

        alert["_id"] = str(alert["_id"])

        alerts.append(alert)

    return alerts