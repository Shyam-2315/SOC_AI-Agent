from datetime import datetime, timezone
import json
from typing import Any

from fastapi import HTTPException
from pymongo.errors import DuplicateKeyError

from app.common.mongo import paginated_response, parse_object_id, serialize_document
from app.common.pagination import Pagination
from app.db.client import detection_rule_packs_collection, detection_rules_collection
from app.schemas.rule import DetectionRuleCreate
from app.services.rules import MITRE_FIELDS, normalize_mitre_metadata
from app.schemas.rule_pack import DetectionPackCreate, DetectionPackUpdate
from app.services.audit import write_audit_event


STARTER_PACKS: dict[str, dict[str, Any]] = {
    "ssh_brute_force": {
        "name": "SSH Brute Force",
        "description": "Detect repeated SSH authentication failures.",
        "category": "authentication",
        "version": "1.0.0",
        "rules": [
            {
                "title": "SSH failed login activity",
                "description": "Failed SSH login events from Linux hosts.",
                "level": "high",
                "event_type": "ssh_attack",
                "detection": {
                    "selection": {"message|contains": "failed login"},
                },
                "tags": ["attack.credential_access", "attack.t1110"],
            }
        ],
    },
    "malware_execution": {
        "name": "Malware Execution",
        "description": "Detect common malware execution signals.",
        "category": "malware",
        "version": "1.0.0",
        "rules": [
            {
                "title": "Suspicious malware execution",
                "description": "Process or endpoint events referencing malware execution.",
                "level": "critical",
                "event_type": "process_execution",
                "detection": {"selection": {"message|contains": "malware"}},
                "tags": ["attack.execution", "attack.t1059"],
            }
        ],
    },
    "ransomware_behavior": {
        "name": "Ransomware Behavior",
        "description": "Detect ransomware-like encryption behavior.",
        "category": "ransomware",
        "version": "1.0.0",
        "rules": [
            {
                "title": "Ransomware encryption activity",
                "description": "File events indicating bulk encryption or ransom notes.",
                "level": "critical",
                "event_type": "file_activity",
                "detection": {"selection": {"message|contains": "ransom"}},
                "tags": ["attack.impact", "attack.t1486"],
            }
        ],
    },
    "suspicious_network_activity": {
        "name": "Suspicious Network Activity",
        "description": "Detect suspicious outbound or scanning network behavior.",
        "category": "network",
        "version": "1.0.0",
        "rules": [
            {
                "title": "Suspicious network connection",
                "description": "Network logs containing suspicious connection activity.",
                "level": "medium",
                "event_type": "connection_attempt",
                "detection": {"selection": {"message|contains": "suspicious"}},
                "tags": ["attack.command_and_control", "attack.t1071"],
            }
        ],
    },
    "privilege_escalation": {
        "name": "Privilege Escalation",
        "description": "Detect privilege escalation attempts.",
        "category": "privilege-escalation",
        "version": "1.0.0",
        "rules": [
            {
                "title": "Privilege escalation attempt",
                "description": "Linux or identity events containing privilege escalation signals.",
                "level": "high",
                "event_type": "privilege_change",
                "detection": {"selection": {"message|contains": "privilege escalation"}},
                "tags": ["attack.privilege_escalation", "attack.t1068"],
            }
        ],
    },
    "mitre_starter_mappings": {
        "name": "MITRE Starter Mappings",
        "description": "Starter ATT&CK mappings for Windows, Linux and syslog telemetry.",
        "category": "mitre",
        "version": "1.0.0",
        "rules": [
            {
                "title": "Windows failed login",
                "description": "Windows authentication failure events.",
                "level": "medium",
                "event_type": "windows_failed_login",
                "detection": {"selection": {"message|contains": "failed"}},
            },
            {
                "title": "Linux SSH failed login",
                "description": "Linux SSH authentication failure events.",
                "level": "medium",
                "event_type": "linux_ssh_failed_login",
                "detection": {"selection": {"message|contains": "failed"}},
            },
            {
                "title": "Linux sudo failure",
                "description": "Linux sudo failure events.",
                "level": "high",
                "event_type": "linux_sudo_failure",
                "detection": {"selection": {"message|contains": "sudo"}},
            },
            {
                "title": "Windows process execution",
                "description": "Windows process execution events.",
                "level": "medium",
                "event_type": "windows_process_execution",
                "detection": {"selection": {"message|contains": "process"}},
            },
            {
                "title": "Linux suspicious process",
                "description": "Linux suspicious process execution events.",
                "level": "high",
                "event_type": "linux_suspicious_process",
                "detection": {"selection": {"message|contains": "suspicious"}},
            },
            {
                "title": "Syslog event",
                "description": "Generic syslog event mapping for discovery activity.",
                "level": "low",
                "event_type": "syslog_event",
                "detection": {"selection": {"message|contains": "syslog"}},
            },
        ],
    },
}


FIELD_ALIASES = {
    "source": "source",
    "event_type": "event_type",
    "eventtype": "event_type",
    "severity": "severity",
    "level": "severity",
    "message": "message",
    "msg": "message",
    "commandline": "message",
    "image": "message",
    "ip": "ip_address",
    "ip_address": "ip_address",
    "src_ip": "ip_address",
    "sourceip": "ip_address",
}


def _serialize_pack(pack: dict[str, Any]) -> dict[str, Any]:
    serialized = serialize_document(pack)
    serialized["id"] = serialized.pop("_id")
    return serialized


def _load_import_payload(raw_body: bytes, content_type: str) -> dict[str, Any]:
    body = raw_body.decode("utf-8").strip()
    if not body:
        raise HTTPException(status_code=400, detail="Import payload is required")

    if "json" in content_type or body.startswith(("{", "[")):
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail="Invalid JSON import payload") from exc
    else:
        try:
            import yaml
        except ModuleNotFoundError as exc:
            raise HTTPException(
                status_code=500,
                detail="YAML import requires PyYAML to be installed",
            ) from exc
        try:
            parsed = yaml.safe_load(body)
        except Exception as exc:
            raise HTTPException(status_code=400, detail="Invalid YAML import payload") from exc

    if isinstance(parsed, list):
        return {"rules": parsed}
    if not isinstance(parsed, dict):
        raise HTTPException(status_code=400, detail="Import payload must be an object or list")
    return parsed


def _extract_mitre(tags: list[Any]) -> tuple[str | None, str | None]:
    tactic = None
    technique = None
    for tag in tags:
        value = str(tag)
        normalized = value.lower()
        if normalized.startswith("attack.t") and technique is None:
            technique = value.replace("attack.", "").upper()
        elif normalized.startswith("attack.") and tactic is None:
            tactic = value.split(".", 1)[1].replace("_", " ").title()
    return tactic, technique


def _condition_from_sigma_key(key: str, value: Any) -> dict[str, str] | None:
    raw_field, _, modifier = key.partition("|")
    normalized = raw_field.replace("-", "_").replace(".", "_").lower()
    field = FIELD_ALIASES.get(normalized)
    if not field:
        return None
    operator = "contains" if modifier.lower() == "contains" else "equals"
    if isinstance(value, list):
        value = value[0] if value else ""
    return {"field": field, "operator": operator, "value": str(value)}


def _conditions_from_sigma(rule: dict[str, Any]) -> list[dict[str, str]]:
    if isinstance(rule.get("conditions"), list):
        return rule["conditions"]

    detection = rule.get("detection") if isinstance(rule.get("detection"), dict) else {}
    selection = detection.get("selection") if isinstance(detection.get("selection"), dict) else {}
    conditions = []
    for key, value in selection.items():
        condition = _condition_from_sigma_key(str(key), value)
        if condition:
            conditions.append(condition)
    if not conditions and isinstance(rule.get("message"), str):
        conditions.append(
            {"field": "message", "operator": "contains", "value": rule["message"]}
        )
    return conditions


def _event_type_from_sigma(rule: dict[str, Any]) -> str | None:
    if rule.get("event_type"):
        return str(rule["event_type"]).lower()
    logsource = rule.get("logsource") if isinstance(rule.get("logsource"), dict) else {}
    category = logsource.get("category") or logsource.get("service") or logsource.get("product")
    return str(category).lower().replace(" ", "_") if category else None


def _rule_payload_from_import(rule: dict[str, Any]) -> DetectionRuleCreate:
    if not isinstance(rule, dict):
        raise HTTPException(status_code=400, detail="Each imported rule must be an object")
    tags = rule.get("tags") if isinstance(rule.get("tags"), list) else []
    mitre_tactic, mitre_technique = _extract_mitre(tags)
    payload = {
        "name": rule.get("name") or rule.get("title"),
        "description": rule.get("description") or "Imported Sigma-style detection rule",
        "severity": rule.get("severity") or rule.get("level") or "medium",
        "event_type": _event_type_from_sigma(rule),
        "conditions": _conditions_from_sigma(rule),
        "mitre_tactic": rule.get("mitre_tactic") or mitre_tactic,
        "mitre_technique": rule.get("mitre_technique") or mitre_technique,
        "enabled": bool(rule.get("enabled", True)),
    }
    payload.update({field: rule.get(field) for field in MITRE_FIELDS if rule.get(field)})
    payload.update(normalize_mitre_metadata(payload))
    try:
        return DetectionRuleCreate.model_validate(payload)
    except Exception as exc:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid imported rule: {payload.get('name') or 'unnamed'}",
        ) from exc


def _pack_payload_from_import(data: dict[str, Any], starter_key: str | None = None) -> DetectionPackCreate:
    pack_data = data.get("pack") if isinstance(data.get("pack"), dict) else data
    return DetectionPackCreate(
        name=pack_data.get("name") or pack_data.get("title") or "Imported Detection Pack",
        description=pack_data.get("description") or "Imported Sigma-style detection pack",
        category=pack_data.get("category") or starter_key or "imported",
        version=str(pack_data.get("version") or "1.0.0"),
        enabled=bool(pack_data.get("enabled", True)),
    )


async def _insert_pack(pack: DetectionPackCreate, user: dict) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    document = {
        "name": pack.name,
        "description": pack.description,
        "category": pack.category,
        "version": pack.version,
        "organization_id": user["organization_id"],
        "rules_count": 0,
        "enabled": pack.enabled,
        "created_by": user["email"],
        "created_at": now,
        "updated_at": now,
    }
    try:
        result = await detection_rule_packs_collection.insert_one(document)
    except DuplicateKeyError as exc:
        raise HTTPException(
            status_code=400,
            detail="Detection pack name and version already exist for this organization",
        ) from exc
    document["_id"] = result.inserted_id
    return document


async def create_pack(pack: DetectionPackCreate, user: dict) -> dict:
    document = await _insert_pack(pack, user)
    await write_audit_event(
        event_type="pack.created",
        actor=user,
        target_type="detection_pack",
        target_id=str(document["_id"]),
        metadata={"name": pack.name, "version": pack.version},
    )
    return {"message": "Detection pack created", "pack": _serialize_pack(document)}


async def list_packs(organization_id: str, pagination: Pagination) -> dict:
    query = {"organization_id": organization_id}
    cursor = (
        detection_rule_packs_collection.find(query)
        .sort("created_at", -1)
        .skip(pagination.offset)
        .limit(pagination.limit)
    )
    items = []
    async for pack in cursor:
        items.append(_serialize_pack(pack))
    total = await detection_rule_packs_collection.count_documents(query)
    return paginated_response(items, total, pagination)


async def get_pack(pack_id: str, organization_id: str) -> dict:
    object_id = parse_object_id(pack_id, "rule pack")
    pack = await detection_rule_packs_collection.find_one(
        {"_id": object_id, "organization_id": organization_id}
    )
    if not pack:
        raise HTTPException(status_code=404, detail="Detection pack not found")
    return _serialize_pack(pack)


async def update_pack(pack_id: str, update: DetectionPackUpdate, user: dict) -> dict:
    object_id = parse_object_id(pack_id, "rule pack")
    update_data = update.model_dump(exclude_none=True)
    if not update_data:
        raise HTTPException(status_code=400, detail="No updates provided")
    update_data["updated_at"] = datetime.now(timezone.utc)

    try:
        result = await detection_rule_packs_collection.update_one(
            {"_id": object_id, "organization_id": user["organization_id"]},
            {"$set": update_data},
        )
    except DuplicateKeyError as exc:
        raise HTTPException(
            status_code=400,
            detail="Detection pack name and version already exist for this organization",
        ) from exc
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Detection pack not found")

    event_type = "pack.updated"
    if "enabled" in update_data:
        await detection_rules_collection.update_many(
            {"pack_id": pack_id, "organization_id": user["organization_id"]},
            {"$set": {"enabled": update_data["enabled"], "updated_at": update_data["updated_at"]}},
        )
        event_type = "pack.enabled" if update_data["enabled"] else "pack.disabled"

    await write_audit_event(
        event_type=event_type,
        actor=user,
        target_type="detection_pack",
        target_id=pack_id,
        metadata={"fields": sorted(update_data.keys())},
    )
    return {
        "message": "Detection pack updated",
        "pack": await get_pack(pack_id, user["organization_id"]),
    }


async def delete_pack(pack_id: str, user: dict) -> dict:
    object_id = parse_object_id(pack_id, "rule pack")
    result = await detection_rule_packs_collection.delete_one(
        {"_id": object_id, "organization_id": user["organization_id"]}
    )
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Detection pack not found")
    await detection_rules_collection.delete_many(
        {"pack_id": pack_id, "organization_id": user["organization_id"]}
    )
    await write_audit_event(
        event_type="pack.deleted",
        actor=user,
        target_type="detection_pack",
        target_id=pack_id,
    )
    return {"message": "Detection pack deleted"}


async def _insert_imported_rules(
    *,
    pack_id: str,
    pack_enabled: bool,
    imported_rules: list[DetectionRuleCreate],
    user: dict,
) -> int:
    now = datetime.now(timezone.utc)
    documents = []
    for rule in imported_rules:
        mitre = normalize_mitre_metadata(rule.model_dump())
        documents.append(
            {
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
                "pack_id": pack_id,
                "enabled": pack_enabled and rule.enabled,
                "organization_id": user["organization_id"],
                "created_by": user["email"],
                "created_at": now,
                "updated_at": now,
            }
        )
    if not documents:
        return 0
    await detection_rules_collection.insert_many(documents)
    return len(documents)


async def import_pack(raw_body: bytes, content_type: str, user: dict) -> dict:
    data = _load_import_payload(raw_body, content_type)
    starter_key = data.get("starter_pack")
    if starter_key:
        if starter_key not in STARTER_PACKS:
            raise HTTPException(status_code=400, detail="Unknown starter pack")
        data = STARTER_PACKS[starter_key]

    rules_data = data.get("rules")
    if rules_data is None and ("title" in data or "detection" in data):
        rules_data = [data]
    if not isinstance(rules_data, list) or not rules_data:
        raise HTTPException(status_code=400, detail="Import payload must include rules")

    pack = _pack_payload_from_import(data, starter_key)
    imported_rules = [_rule_payload_from_import(rule) for rule in rules_data]
    pack_document = await _insert_pack(pack, user)
    pack_id = str(pack_document["_id"])
    try:
        rules_count = await _insert_imported_rules(
            pack_id=pack_id,
            pack_enabled=pack.enabled,
            imported_rules=imported_rules,
            user=user,
        )
    except DuplicateKeyError as exc:
        await detection_rule_packs_collection.delete_one({"_id": pack_document["_id"]})
        await detection_rules_collection.delete_many(
            {"organization_id": user["organization_id"], "pack_id": pack_id}
        )
        raise HTTPException(
            status_code=400,
            detail="Imported rule names must be unique within the organization",
        ) from exc
    await detection_rule_packs_collection.update_one(
        {"_id": pack_document["_id"]},
        {"$set": {"rules_count": rules_count, "updated_at": datetime.now(timezone.utc)}},
    )
    pack_document["rules_count"] = rules_count
    await write_audit_event(
        event_type="pack.imported",
        actor=user,
        target_type="detection_pack",
        target_id=pack_id,
        metadata={"rules_count": rules_count, "starter_pack": starter_key},
    )
    return {"message": "Detection pack imported", "pack": _serialize_pack(pack_document)}


async def list_starter_packs() -> dict:
    return {
        "items": [
            {
                "key": key,
                "name": pack["name"],
                "description": pack["description"],
                "category": pack["category"],
                "version": pack["version"],
                "rules_count": len(pack["rules"]),
            }
            for key, pack in STARTER_PACKS.items()
        ]
    }


async def export_pack(pack_id: str, organization_id: str, user: dict, export_format: str) -> Any:
    pack = await get_pack(pack_id, organization_id)
    rules = []
    cursor = detection_rules_collection.find(
        {"organization_id": organization_id, "pack_id": pack_id}
    ).sort("created_at", 1)
    async for rule in cursor:
        rules.append(serialize_document(rule))

    payload = {
        "pack": {
            "name": pack["name"],
            "description": pack["description"],
            "category": pack["category"],
            "version": pack["version"],
            "enabled": pack["enabled"],
        },
        "rules": [_export_rule(rule) for rule in rules],
    }
    await write_audit_event(
        event_type="pack.exported",
        actor=user,
        target_type="detection_pack",
        target_id=pack_id,
        metadata={"format": export_format, "rules_count": len(rules)},
    )
    if export_format == "json":
        return payload
    if export_format in {"yaml", "yml"}:
        try:
            import yaml
        except ModuleNotFoundError as exc:
            raise HTTPException(
                status_code=500,
                detail="YAML export requires PyYAML to be installed",
            ) from exc
        return yaml.safe_dump(payload, sort_keys=False)
    raise HTTPException(status_code=400, detail="Export format must be json or yaml")


def _export_rule(rule: dict[str, Any]) -> dict[str, Any]:
    tags = []
    if rule.get("mitre_tactic"):
        tags.append("attack." + str(rule["mitre_tactic"]).lower().replace(" ", "_"))
    if rule.get("mitre_technique"):
        tags.append("attack." + str(rule["mitre_technique"]).lower())
    if rule.get("mitre_tactic_id"):
        tags.append("attack." + str(rule["mitre_tactic_id"]).lower())
    if rule.get("mitre_technique_id"):
        tags.append("attack." + str(rule["mitre_technique_id"]).lower())
    selection = {}
    for condition in rule.get("conditions", []):
        key = condition["field"]
        if condition.get("operator") == "contains":
            key = f"{key}|contains"
        selection[key] = condition.get("value")
    return {
        "title": rule["name"],
        "description": rule["description"],
        "level": rule["severity"],
        "event_type": rule.get("event_type"),
        "detection": {
            "selection": selection,
            "condition": "selection",
        },
        "enabled": rule.get("enabled", True),
        "tags": tags,
        "mitre_tactic_id": rule.get("mitre_tactic_id"),
        "mitre_tactic_name": rule.get("mitre_tactic_name"),
        "mitre_technique_id": rule.get("mitre_technique_id"),
        "mitre_technique_name": rule.get("mitre_technique_name"),
        "mitre_subtechnique_id": rule.get("mitre_subtechnique_id"),
        "mitre_subtechnique_name": rule.get("mitre_subtechnique_name"),
    }
