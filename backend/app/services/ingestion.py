from datetime import datetime, timezone

from fastapi import HTTPException

from ai.campaign_detector import detect_attack_campaign
from ai.mitre_mapper import map_to_mitre
from ai.response_engine import generate_response
from ai.threat_classifier import classify_threat
from ai.threat_intel import check_ip_reputation
from app.common.mongo import serialize_document
from app.core.config import settings
from app.core.logging import get_logger
from app.db.client import (
    alerts_collection,
    alert_processing_jobs_collection,
    incidents_collection,
    logs_collection,
    response_actions_collection,
)
from app.realtime.events import build_realtime_event
from app.realtime.pubsub import publish_realtime_event
from app.schemas.log import LogModel
from app.services.audit import write_audit_event


logger = get_logger(__name__)


def _build_log_context(
    data: LogModel,
    organization_id: str,
) -> dict:
    threat_result = classify_threat(
        data.event_type,
        data.severity,
        data.message,
    )
    mitre = map_to_mitre(data.event_type)
    mitre_tactic = mitre["tactic"]
    mitre_technique = (
        f"{mitre['technique_id']} - {mitre['technique_name']}"
        if mitre["technique_id"] != "Unknown"
        else "Unknown"
    )
    ip_reputation = check_ip_reputation(str(data.ip_address))

    return {
        "source": data.source,
        "event_type": data.event_type,
        "severity": data.severity,
        "message": data.message,
        "ip_address": str(data.ip_address),
        "organization_id": organization_id,
        "threat_score": threat_result["threat_score"],
        "threat_label": threat_result["label"],
        "mitre_tactic": mitre_tactic,
        "mitre_technique": mitre_technique,
        "ip_reputation": ip_reputation,
        "alert_generated": (
            threat_result["label"] == "malicious" or data.severity.lower() == "critical"
        ),
    }


async def _store_log(context: dict) -> str:
    log_document = {
        "source": context["source"],
        "event_type": context["event_type"],
        "severity": context["severity"],
        "message": context["message"],
        "ip_address": context["ip_address"],
        "organization_id": context["organization_id"],
        "threat_score": context["threat_score"],
        "threat_label": context["threat_label"],
        "mitre_tactic": context["mitre_tactic"],
        "mitre_technique": context["mitre_technique"],
        "ip_reputation": context["ip_reputation"],
        "timestamp": datetime.now(timezone.utc),
    }
    result = await logs_collection.insert_one(log_document)
    return str(result.inserted_id)


def _build_alert_context(
    log_context: dict,
    log_id: str,
) -> dict:
    return {
        **log_context,
        "log_id": log_id,
    }


def _serialize_job(document: dict) -> dict:
    serialized = serialize_document(document)
    return {
        "id": serialized["_id"],
        "task_id": serialized["task_id"],
        "organization_id": serialized["organization_id"],
        "log_id": serialized["log_id"],
        "status": serialized["status"],
        "processing_mode": serialized["processing_mode"],
        "created_at": serialized.get("created_at"),
        "updated_at": serialized.get("updated_at"),
        "started_at": serialized.get("started_at"),
        "completed_at": serialized.get("completed_at"),
        "result": serialized.get("result"),
        "error": serialized.get("error"),
    }


async def _create_alert_job(
    task_id: str,
    alert_context: dict,
) -> None:
    now = datetime.now(timezone.utc)
    await alert_processing_jobs_collection.update_one(
        {"task_id": task_id},
        {
            "$set": {
                "task_id": task_id,
                "organization_id": alert_context["organization_id"],
                "log_id": alert_context["log_id"],
                "status": "queued",
                "processing_mode": "celery",
                "updated_at": now,
            },
            "$setOnInsert": {
                "created_at": now,
            },
        },
        upsert=True,
    )


async def _enqueue_alert_processing(alert_context: dict) -> str:
    if not settings.celery_enabled:
        raise HTTPException(
            status_code=503,
            detail="Celery alert processing is not enabled",
        )

    from app.workers.celery_app import celery_app

    task_result = celery_app.send_task(
        "app.workers.tasks.process_alert_job",
        kwargs={"alert_context": alert_context},
        queue=settings.celery_task_default_queue,
    )
    await _create_alert_job(task_result.id, alert_context)
    return task_result.id


async def mark_alert_job_failed(
    task_id: str,
    organization_id: str,
    error: str,
) -> None:
    now = datetime.now(timezone.utc)
    await alert_processing_jobs_collection.update_one(
        {"task_id": task_id},
        {
            "$set": {
                "organization_id": organization_id,
                "status": "failed",
                "error": error,
                "updated_at": now,
                "completed_at": now,
            },
            "$setOnInsert": {
                "created_at": now,
                "processing_mode": "celery",
            },
        },
        upsert=True,
    )


async def mark_alert_job_retrying(
    task_id: str,
    organization_id: str,
    error: str,
) -> None:
    now = datetime.now(timezone.utc)
    await alert_processing_jobs_collection.update_one(
        {"task_id": task_id},
        {
            "$set": {
                "organization_id": organization_id,
                "status": "retrying",
                "error": error,
                "updated_at": now,
            },
            "$setOnInsert": {
                "created_at": now,
                "processing_mode": "celery",
            },
        },
        upsert=True,
    )


async def process_alert_job(
    alert_context: dict,
    task_id: str,
) -> dict:
    now = datetime.now(timezone.utc)
    await alert_processing_jobs_collection.update_one(
        {"task_id": task_id},
        {
            "$set": {
                "organization_id": alert_context["organization_id"],
                "log_id": alert_context["log_id"],
                "status": "processing",
                "processing_mode": "celery",
                "started_at": now,
                "updated_at": now,
            },
            "$setOnInsert": {
                "created_at": now,
            },
        },
        upsert=True,
    )

    result = await _process_alert_artifacts(alert_context)

    completed_at = datetime.now(timezone.utc)
    await alert_processing_jobs_collection.update_one(
        {"task_id": task_id},
        {
            "$set": {
                "status": "completed",
                "result": result,
                "updated_at": completed_at,
                "completed_at": completed_at,
            }
        },
    )
    return result


async def _process_alert_artifacts(alert_context: dict) -> dict:
    alert_data = {
        "log_id": alert_context["log_id"],
        "source": alert_context["source"],
        "event_type": alert_context["event_type"],
        "severity": alert_context["severity"],
        "message": alert_context["message"],
        "ip_address": alert_context["ip_address"],
        "organization_id": alert_context["organization_id"],
        "threat_score": alert_context["threat_score"],
        "threat_label": alert_context["threat_label"],
        "mitre_tactic": alert_context["mitre_tactic"],
        "mitre_technique": alert_context["mitre_technique"],
        "ip_reputation": alert_context["ip_reputation"],
        "status": "open",
        "timestamp": datetime.now(timezone.utc),
    }
    alert_result = await alerts_collection.insert_one(alert_data)

    automated_response = generate_response(alert_data)
    response_action_data = {
        "alert_id": str(alert_result.inserted_id),
        "log_id": alert_context["log_id"],
        "organization_id": alert_context["organization_id"],
        "event_type": alert_context["event_type"],
        "severity": alert_context["severity"],
        "ip_address": alert_context["ip_address"],
        "automated_actions": automated_response["automated_actions"],
        "blocked_ips": automated_response["blocked_ips"],
        "status": "simulated",
        "timestamp": datetime.now(timezone.utc),
    }
    response_action_result = await response_actions_collection.insert_one(
        response_action_data
    )
    await write_audit_event(
        event_type="soar.response_action.created",
        organization_id=alert_context["organization_id"],
        target_type="response_action",
        target_id=str(response_action_result.inserted_id),
        metadata={
            "alert_id": str(alert_result.inserted_id),
            "event_type": alert_context["event_type"],
            "status": response_action_data["status"],
        },
    )

    incident_data = {
        "alert_id": str(alert_result.inserted_id),
        "title": f"{alert_context['event_type']} incident detected",
        "severity": alert_context["severity"],
        "status": "open",
        "assigned_to": None,
        "organization_id": alert_context["organization_id"],
        "timestamp": datetime.now(timezone.utc),
    }
    incident_result = await incidents_collection.insert_one(incident_data)

    campaign_result = await detect_attack_campaign(
        alert_context["ip_address"],
        alert_context["organization_id"],
    )
    alert_event = build_realtime_event(
        event_type="soc.alert.created",
        organization_id=alert_context["organization_id"],
        payload={
            "alert_id": str(alert_result.inserted_id),
            "event_type": alert_context["event_type"],
            "severity": alert_context["severity"],
            "message": alert_context["message"],
            "ip_address": alert_context["ip_address"],
            "log_id": alert_context["log_id"],
            "threat_score": alert_context["threat_score"],
            "mitre_tactic": alert_context["mitre_tactic"],
            "mitre_technique": alert_context["mitre_technique"],
            "campaign_detected": campaign_result.get("campaign_detected", False),
            "ip_reputation": alert_context["ip_reputation"],
            "automated_response": automated_response,
        },
    )
    incident_event = build_realtime_event(
        event_type="soc.incident.created",
        organization_id=alert_context["organization_id"],
        payload={
            "incident_id": str(incident_result.inserted_id),
            "alert_id": str(alert_result.inserted_id),
            "title": incident_data["title"],
            "severity": incident_data["severity"],
            "status": incident_data["status"],
            "timestamp": incident_data["timestamp"],
        },
    )
    response_action_event = build_realtime_event(
        event_type="soc.response_action.created",
        organization_id=alert_context["organization_id"],
        payload={
            "response_action_id": str(response_action_result.inserted_id),
            "alert_id": str(alert_result.inserted_id),
            "log_id": alert_context["log_id"],
            "event_type": alert_context["event_type"],
            "automated_actions": automated_response["automated_actions"],
            "blocked_ips": automated_response["blocked_ips"],
            "status": response_action_data["status"],
            "timestamp": response_action_data["timestamp"],
        },
    )
    await publish_realtime_event(alert_event)
    await publish_realtime_event(incident_event)
    await publish_realtime_event(response_action_event)

    return {
        "alert_id": str(alert_result.inserted_id),
        "response_action_id": str(response_action_result.inserted_id),
        "incident_id": str(incident_result.inserted_id),
        "campaign_detected": campaign_result.get("campaign_detected", False),
    }


async def ingest_log(
    data: LogModel,
    organization_id: str,
    *,
    force_background: bool = False,
) -> dict:
    log_context = _build_log_context(data, organization_id)
    log_id = await _store_log(log_context)

    task_id = None
    processing_mode = "sync"
    alert_processing_status = "skipped"

    if log_context["alert_generated"]:
        alert_context = _build_alert_context(log_context, log_id)
        use_background_processing = force_background or settings.celery_enabled
        if use_background_processing:
            task_id = await _enqueue_alert_processing(alert_context)
            processing_mode = "celery"
            alert_processing_status = "queued"
        else:
            await _process_alert_artifacts(alert_context)
            alert_processing_status = "completed"

    response = {
        "message": "Log ingested successfully",
        "log_id": log_id,
        "organization_id": organization_id,
        "threat_analysis": {
            "threat_score": log_context["threat_score"],
            "label": log_context["threat_label"],
        },
        "ip_reputation": log_context["ip_reputation"],
        "alert_generated": log_context["alert_generated"],
        "processing_mode": processing_mode,
        "alert_processing_status": alert_processing_status,
    }
    if task_id is not None:
        response["task_id"] = task_id
    return response


async def get_alert_job_status(
    task_id: str,
    organization_id: str,
) -> dict:
    job = await alert_processing_jobs_collection.find_one(
        {
            "task_id": task_id,
            "organization_id": organization_id,
        }
    )
    if not job:
        raise HTTPException(status_code=404, detail="Alert processing task not found")

    return _serialize_job(job)
