from datetime import datetime, timezone
from typing import Any, Optional

from bson import ObjectId
from fastapi import HTTPException

from app.common.mongo import paginated_response, parse_object_id, serialize_document
from app.common.pagination import Pagination
from app.core.logging import get_logger
from app.db.client import detection_rules_collection
from app.schemas.rule import DetectionRuleCreate, DetectionRuleUpdate
from app.services.audit import write_audit_event


logger = get_logger(__name__)

SEVERITY_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


STARTER_MITRE_MAPPINGS: dict[str, dict[str, str]] = {
    "windows_failed_login": {
        "mitre_tactic_id": "TA0006",
        "mitre_tactic_name": "Credential Access",
        "mitre_technique_id": "T1110",
        "mitre_technique_name": "Brute Force",
    },
    "linux_ssh_failed_login": {
        "mitre_tactic_id": "TA0006",
        "mitre_tactic_name": "Credential Access",
        "mitre_technique_id": "T1110",
        "mitre_technique_name": "Brute Force",
    },
    "ssh_attack": {
        "mitre_tactic_id": "TA0006",
        "mitre_tactic_name": "Credential Access",
        "mitre_technique_id": "T1110",
        "mitre_technique_name": "Brute Force",
    },
    "linux_sudo_failure": {
        "mitre_tactic_id": "TA0004",
        "mitre_tactic_name": "Privilege Escalation",
        "mitre_technique_id": "T1548.003",
        "mitre_technique_name": "Sudo and Sudo Caching",
    },
    "windows_process_execution": {
        "mitre_tactic_id": "TA0002",
        "mitre_tactic_name": "Execution",
        "mitre_technique_id": "T1059",
        "mitre_technique_name": "Command and Scripting Interpreter",
    },
    "linux_suspicious_process": {
        "mitre_tactic_id": "TA0002",
        "mitre_tactic_name": "Execution",
        "mitre_technique_id": "T1059.004",
        "mitre_technique_name": "Unix Shell",
    },
    "syslog_event": {
        "mitre_tactic_id": "TA0007",
        "mitre_tactic_name": "Discovery",
        "mitre_technique_id": "T1082",
        "mitre_technique_name": "System Information Discovery",
    },
}

MITRE_FIELDS = (
    "mitre_tactic_id",
    "mitre_tactic_name",
    "mitre_technique_id",
    "mitre_technique_name",
    "mitre_subtechnique_id",
    "mitre_subtechnique_name",
)


def normalize_mitre_metadata(data: dict[str, Any]) -> dict[str, Any]:
    event_type = data.get("event_type")
    metadata = dict(STARTER_MITRE_MAPPINGS.get(str(event_type or "").lower(), {}))

    if data.get("mitre_tactic") and not metadata.get("mitre_tactic_name"):
        metadata["mitre_tactic_name"] = data["mitre_tactic"]
    if data.get("mitre_technique") and not metadata.get("mitre_technique_id"):
        technique = str(data["mitre_technique"])
        technique_id, _, technique_name = technique.partition(" - ")
        metadata["mitre_technique_id"] = technique_id
        if technique_name:
            metadata["mitre_technique_name"] = technique_name

    for field in MITRE_FIELDS:
        if data.get(field):
            metadata[field] = data[field]

    if metadata.get("mitre_tactic_name") and not data.get("mitre_tactic"):
        metadata["mitre_tactic"] = metadata["mitre_tactic_name"]
    else:
        metadata["mitre_tactic"] = data.get("mitre_tactic")

    if metadata.get("mitre_technique_id") and metadata.get("mitre_technique_name"):
        metadata["mitre_technique"] = (
            f"{metadata['mitre_technique_id']} - {metadata['mitre_technique_name']}"
        )
    else:
        metadata["mitre_technique"] = data.get("mitre_technique")

    return metadata


def _serialize_rule(rule: dict) -> dict:
    serialized = serialize_document(rule)
    serialized["id"] = serialized.pop("_id")
    serialized.update(normalize_mitre_metadata(serialized))
    return serialized


async def create_rule(rule: DetectionRuleCreate, user: dict) -> dict:
    now = datetime.now(timezone.utc)
    mitre = normalize_mitre_metadata(rule.model_dump())
    document = {
        "name": rule.name,
        "description": rule.description,
        "severity": rule.severity,
        "event_type": rule.event_type,
        "conditions": [condition.model_dump() for condition in rule.conditions],
        "mitre_tactic": mitre.get("mitre_tactic"),
        "mitre_technique": mitre.get("mitre_technique"),
        "mitre_tactic_id": mitre.get("mitre_tactic_id"),
        "mitre_tactic_name": mitre.get("mitre_tactic_name"),
        "mitre_technique_id": mitre.get("mitre_technique_id"),
        "mitre_technique_name": mitre.get("mitre_technique_name"),
        "mitre_subtechnique_id": mitre.get("mitre_subtechnique_id"),
        "mitre_subtechnique_name": mitre.get("mitre_subtechnique_name"),
        "pack_id": rule.pack_id,
        "enabled": rule.enabled,
        "organization_id": user["organization_id"],
        "created_by": user["email"],
        "created_at": now,
        "updated_at": now,
    }
    result = await detection_rules_collection.insert_one(document)
    document["_id"] = result.inserted_id
    await write_audit_event(
        event_type="rule.created",
        actor=user,
        target_type="detection_rule",
        target_id=str(result.inserted_id),
        metadata={"name": rule.name, "severity": rule.severity},
    )
    return {"message": "Rule created", "rule": _serialize_rule(document)}


async def list_rules(organization_id: str, pagination: Pagination) -> dict:
    query = {"organization_id": organization_id}
    items = []
    cursor = (
        detection_rules_collection.find(query)
        .sort("created_at", -1)
        .skip(pagination.offset)
        .limit(pagination.limit)
    )
    async for rule in cursor:
        items.append(_serialize_rule(rule))
    total = await detection_rules_collection.count_documents(query)
    return paginated_response(items, total, pagination)


async def get_rule(rule_id: str, organization_id: str) -> dict:
    object_id = parse_object_id(rule_id, "rule")
    rule = await detection_rules_collection.find_one(
        {"_id": object_id, "organization_id": organization_id}
    )
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return _serialize_rule(rule)


async def update_rule(rule_id: str, update: DetectionRuleUpdate, user: dict) -> dict:
    object_id = parse_object_id(rule_id, "rule")
    update_data = update.model_dump(exclude_none=True)
    if "conditions" in update_data:
        update_data["conditions"] = [
            condition.model_dump() for condition in update.conditions or []
        ]
    if any(field in update_data for field in (*MITRE_FIELDS, "mitre_tactic", "mitre_technique", "event_type")):
        update_data.update(normalize_mitre_metadata(update_data))
    if not update_data:
        raise HTTPException(status_code=400, detail="No updates provided")
    update_data["updated_at"] = datetime.now(timezone.utc)

    result = await detection_rules_collection.update_one(
        {"_id": object_id, "organization_id": user["organization_id"]},
        {"$set": update_data},
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Rule not found")

    await write_audit_event(
        event_type="rule.updated",
        actor=user,
        target_type="detection_rule",
        target_id=rule_id,
        metadata={"fields": sorted(update_data.keys())},
    )
    return {"message": "Rule updated", "rule": await get_rule(rule_id, user["organization_id"])}


async def delete_rule(rule_id: str, user: dict) -> dict:
    object_id = parse_object_id(rule_id, "rule")
    result = await detection_rules_collection.delete_one(
        {"_id": object_id, "organization_id": user["organization_id"]}
    )
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Rule not found")
    await write_audit_event(
        event_type="rule.deleted",
        actor=user,
        target_type="detection_rule",
        target_id=rule_id,
    )
    return {"message": "Rule deleted"}


async def load_enabled_rules(organization_id: str) -> list[dict]:
    rules = []
    cursor = detection_rules_collection.find(
        {"organization_id": organization_id, "enabled": True}
    ).sort("severity", -1)
    async for rule in cursor:
        rules.append(rule)
    return sorted(
        rules,
        key=lambda item: SEVERITY_RANK.get(item.get("severity", "low"), 0),
        reverse=True,
    )


def _condition_matches(log_context: dict, condition: dict[str, Any]) -> bool:
    field = condition.get("field")
    operator = condition.get("operator", "equals")
    expected = str(condition.get("value", "")).lower()
    actual = str(log_context.get(field, "")).lower()

    if operator == "equals":
        return actual == expected
    if operator == "contains":
        return expected in actual
    return False


def _rule_matches(log_context: dict, rule: dict) -> bool:
    event_type = rule.get("event_type")
    if event_type and log_context.get("event_type") != event_type:
        return False
    return all(_condition_matches(log_context, condition) for condition in rule.get("conditions", []))


async def evaluate_rules(log_context: dict) -> Optional[dict]:
    for rule in await load_enabled_rules(log_context["organization_id"]):
        logger.info(
            "detection rule evaluated",
            extra={
                "organization_id": log_context["organization_id"],
                "event_type": log_context.get("event_type"),
                "rule_id": str(rule["_id"]),
                "rule_name": rule.get("name"),
            },
        )
        if _rule_matches(log_context, rule):
            mitre = normalize_mitre_metadata(rule)
            logger.info(
                "detection rule matched",
                extra={
                    "organization_id": log_context["organization_id"],
                    "event_type": log_context.get("event_type"),
                    "rule_id": str(rule["_id"]),
                    "rule_name": rule.get("name"),
                },
            )
            return {
                "id": str(rule["_id"]),
                "name": rule["name"],
                "severity": rule["severity"],
                "mitre_tactic": mitre.get("mitre_tactic"),
                "mitre_technique": mitre.get("mitre_technique"),
                "mitre_tactic_id": mitre.get("mitre_tactic_id"),
                "mitre_tactic_name": mitre.get("mitre_tactic_name"),
                "mitre_technique_id": mitre.get("mitre_technique_id"),
                "mitre_technique_name": mitre.get("mitre_technique_name"),
                "mitre_subtechnique_id": mitre.get("mitre_subtechnique_id"),
                "mitre_subtechnique_name": mitre.get("mitre_subtechnique_name"),
            }
    return None
