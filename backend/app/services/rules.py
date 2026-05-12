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


def _serialize_rule(rule: dict) -> dict:
    serialized = serialize_document(rule)
    serialized["id"] = serialized.pop("_id")
    return serialized


async def create_rule(rule: DetectionRuleCreate, user: dict) -> dict:
    now = datetime.now(timezone.utc)
    document = {
        "name": rule.name,
        "description": rule.description,
        "severity": rule.severity,
        "event_type": rule.event_type,
        "conditions": [condition.model_dump() for condition in rule.conditions],
        "mitre_tactic": rule.mitre_tactic,
        "mitre_technique": rule.mitre_technique,
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
                "mitre_tactic": rule.get("mitre_tactic"),
                "mitre_technique": rule.get("mitre_technique"),
            }
    return None
