# backend/api/routes/ingestion.py

from datetime import datetime, timezone

from fastapi import APIRouter, Depends

from models.log_model import LogModel

from core.database import (
    logs_collection,
    alerts_collection,
    incidents_collection,
    response_actions_collection,
)
from core.dependencies import get_collector_organization_id

from ai.threat_classifier import classify_threat
from ai.campaign_detector import detect_attack_campaign
from ai.mitre_mapper import map_to_mitre
from ai.response_engine import generate_response
from ai.threat_intel import check_ip_reputation

from websocket.manager import manager

router = APIRouter(
    prefix="/ingest",
    tags=["Log Ingestion"]
)


@router.post("/")
async def ingest_log(
    data: LogModel,
    organization_id: str = Depends(get_collector_organization_id),
):

    # =========================
    # AI THREAT CLASSIFICATION
    # =========================

    threat_result = classify_threat(
        data.event_type,
        data.severity,
        data.message
    )

    mitre = map_to_mitre(data.event_type)
    mitre_tactic = mitre["tactic"]
    mitre_technique = (
        f"{mitre['technique_id']} - {mitre['technique_name']}"
        if mitre["technique_id"] != "Unknown"
        else "Unknown"
    )
    ip_reputation = check_ip_reputation(str(data.ip_address))

    # =========================
    # LOG DOCUMENT
    # =========================

    log_data = {

        "source": data.source,
        "event_type": data.event_type,
        "severity": data.severity,
        "message": data.message,
        "ip_address": str(data.ip_address),

        # MULTI TENANT
        "organization_id":
            organization_id,

        # AI
        "threat_score":
            threat_result["threat_score"],

        "threat_label":
            threat_result["label"],

        # MITRE
        "mitre_tactic":
            mitre_tactic,

        "mitre_technique":
            mitre_technique,

        "ip_reputation":
            ip_reputation,

        "timestamp":
            datetime.now(timezone.utc)
    }

    # =========================
    # STORE LOG
    # =========================

    log_result = await logs_collection.insert_one(
        log_data
    )

    # =========================
    # ALERT GENERATION
    # =========================

    generated_alert = False

    if (
        threat_result["label"] == "malicious"
        or data.severity.lower() == "critical"
    ):

        generated_alert = True

        alert_data = {

            "log_id":
                str(log_result.inserted_id),

            "source":
                data.source,

            "event_type":
                data.event_type,

            "severity":
                data.severity,

            "message":
                data.message,

            "ip_address":
                str(data.ip_address),

            # MULTI TENANT
            "organization_id":
                organization_id,

            # AI
            "threat_score":
                threat_result["threat_score"],

            "threat_label":
                threat_result["label"],

            # MITRE
            "mitre_tactic":
                mitre_tactic,

            "mitre_technique":
                mitre_technique,

            "ip_reputation":
                ip_reputation,

            "status":
                "open",

            "timestamp":
                datetime.now(timezone.utc)
        }

        alert_result = await alerts_collection.insert_one(
            alert_data
        )

        automated_response = generate_response(alert_data)
        response_action_data = {
            "alert_id": str(alert_result.inserted_id),
            "log_id": str(log_result.inserted_id),
            "organization_id": organization_id,
            "event_type": data.event_type,
            "severity": data.severity,
            "ip_address": str(data.ip_address),
            "automated_actions": automated_response["automated_actions"],
            "blocked_ips": automated_response["blocked_ips"],
            "status": "simulated",
            "timestamp": datetime.now(timezone.utc),
        }

        await response_actions_collection.insert_one(response_action_data)

        # =========================
        # INCIDENT GENERATION
        # =========================

        incident_data = {

            "alert_id":
                str(alert_result.inserted_id),

            "title":
                f"{data.event_type} incident detected",

            "severity":
                data.severity,

            "status":
                "open",

            "assigned_to":
                None,

            "organization_id":
                organization_id,

            "timestamp":
                datetime.now(timezone.utc)
        }

        await incidents_collection.insert_one(
            incident_data
        )

        # =========================
        # CAMPAIGN DETECTION
        # =========================

        campaign_result = await detect_attack_campaign(
            str(data.ip_address),
            organization_id
        )

        # =========================
        # WEBSOCKET ALERT PUSH
        # =========================

        websocket_payload = {

            "type": "alert",

            "data": {

                "event_type":
                    data.event_type,

                "severity":
                    data.severity,

                "message":
                    data.message,

                "ip_address":
                    str(data.ip_address),

                "organization_id":
                    organization_id,

                "threat_score":
                    threat_result["threat_score"],

                "mitre_tactic":
                    mitre_tactic,

                "mitre_technique":
                    mitre_technique,

                "campaign_detected":
                    campaign_result.get(
                        "campaign_detected",
                        False
                    ),

                "ip_reputation":
                    ip_reputation,

                "automated_response":
                    automated_response
            }
        }

        await manager.broadcast(
            websocket_payload,
            organization_id=organization_id,
        )

    # =========================
    # FINAL RESPONSE
    # =========================

    return {

        "message":
            "Log ingested successfully",

        "log_id":
            str(log_result.inserted_id),

        "organization_id":
            organization_id,

        "threat_analysis": {

            "threat_score":
                threat_result["threat_score"],

            "label":
                threat_result["label"]
        },

        "ip_reputation":
            ip_reputation,

        "mitre_attack": {

            "tactic":
                mitre_tactic,

            "technique":
                mitre_technique
        },

        "alert_generated":
            generated_alert
    }
