import asyncio
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sys
from typing import Any


if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from app.core.security import UserRole, hash_password
from app.db import close_database, create_indexes
from app.db.client import (
    alerts_collection,
    collectors_collection,
    detection_rule_packs_collection,
    detection_rules_collection,
    incidents_collection,
    logs_collection,
    organizations_collection,
    response_actions_collection,
    users_collection,
)
from app.services.collectors import hash_collector_token
from app.services.rule_packs import STARTER_PACKS


DEMO_ORG_NAME = os.getenv("DEMO_ORG_NAME", "Demo SOC")
DEMO_ADMIN_EMAIL = os.getenv("DEMO_ADMIN_EMAIL", "demo.admin@aisoc.dev")
DEMO_ANALYST_EMAIL = os.getenv("DEMO_ANALYST_EMAIL", "demo.analyst@aisoc.dev")
DEMO_VIEWER_EMAIL = os.getenv("DEMO_VIEWER_EMAIL", "demo.viewer@aisoc.dev")
DEMO_ADMIN_PASSWORD = os.getenv("DEMO_ADMIN_PASSWORD", "DemoAdmin123!")
DEMO_ANALYST_PASSWORD = os.getenv("DEMO_ANALYST_PASSWORD", DEMO_ADMIN_PASSWORD)
DEMO_VIEWER_PASSWORD = os.getenv("DEMO_VIEWER_PASSWORD", DEMO_ADMIN_PASSWORD)
DEMO_COLLECTOR_TOKEN = os.getenv("DEMO_COLLECTOR_TOKEN", "demo-collector-token")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


async def upsert_organization() -> str:
    now = utcnow()
    result = await organizations_collection.update_one(
        {"name": DEMO_ORG_NAME},
        {
            "$set": {"updated_at": now},
            "$setOnInsert": {
                "name": DEMO_ORG_NAME,
                "created_at": now,
                "created_by": "demo-seed",
            },
        },
        upsert=True,
    )
    if result.upserted_id:
        return str(result.upserted_id)
    organization = await organizations_collection.find_one({"name": DEMO_ORG_NAME})
    return str(organization["_id"])


async def upsert_user(
    *,
    username: str,
    email: str,
    password: str,
    role: UserRole,
    organization_id: str,
) -> None:
    now = utcnow()
    await users_collection.update_one(
        {"email": email},
        {
            "$set": {
                "username": username,
                "email": email,
                "role": role.value,
                "organization_id": organization_id,
                "disabled": False,
                "updated_at": now,
            },
            "$setOnInsert": {
                "password": hash_password(password),
                "created_at": now,
                "created_by": "demo-seed",
            },
        },
        upsert=True,
    )


async def seed_users(organization_id: str) -> None:
    await upsert_user(
        username="Demo Admin",
        email=DEMO_ADMIN_EMAIL,
        password=DEMO_ADMIN_PASSWORD,
        role=UserRole.admin,
        organization_id=organization_id,
    )
    await upsert_user(
        username="Demo Analyst",
        email=DEMO_ANALYST_EMAIL,
        password=DEMO_ANALYST_PASSWORD,
        role=UserRole.analyst,
        organization_id=organization_id,
    )
    await upsert_user(
        username="Demo Viewer",
        email=DEMO_VIEWER_EMAIL,
        password=DEMO_VIEWER_PASSWORD,
        role=UserRole.viewer,
        organization_id=organization_id,
    )


async def seed_collectors(organization_id: str) -> None:
    now = utcnow()
    collectors = [
        ("Demo Linux Agent", "linux", DEMO_COLLECTOR_TOKEN, "active"),
        ("Demo Firewall Collector", "firewall", f"{DEMO_COLLECTOR_TOKEN}-firewall", "active"),
        ("Demo Cloud Trail Collector", "cloud", f"{DEMO_COLLECTOR_TOKEN}-cloud", "disabled"),
    ]
    for name, collector_type, token, status in collectors:
        await collectors_collection.update_one(
            {"organization_id": organization_id, "name": name},
            {
                "$set": {
                    "type": collector_type,
                    "api_key_hash": hash_collector_token(token),
                    "status": status,
                    "last_seen_at": now - timedelta(minutes=12) if status == "active" else None,
                    "updated_at": now,
                },
                "$setOnInsert": {
                    "name": name,
                    "organization_id": organization_id,
                    "created_at": now,
                },
            },
            upsert=True,
        )


def sigma_rule_to_document(
    rule: dict[str, Any],
    *,
    pack_id: str,
    organization_id: str,
    created_by: str,
) -> dict[str, Any]:
    now = utcnow()
    selection = rule.get("detection", {}).get("selection", {})
    conditions = []
    for key, value in selection.items():
        field, _, modifier = key.partition("|")
        normalized_field = {
            "message": "message",
            "ip": "ip_address",
            "ip_address": "ip_address",
            "event_type": "event_type",
            "severity": "severity",
            "source": "source",
        }.get(field, "message")
        conditions.append(
            {
                "field": normalized_field,
                "operator": "contains" if modifier == "contains" else "equals",
                "value": str(value),
            }
        )
    if not conditions:
        conditions = [{"field": "message", "operator": "contains", "value": rule["title"]}]

    tags = [str(tag) for tag in rule.get("tags", [])]
    tactic = None
    technique = None
    for tag in tags:
        if tag.startswith("attack.t") and technique is None:
            technique = tag.replace("attack.", "").upper()
        elif tag.startswith("attack.") and tactic is None:
            tactic = tag.split(".", 1)[1].replace("_", " ").title()

    return {
        "name": rule["title"],
        "description": rule.get("description", "Demo detection rule"),
        "severity": rule.get("level", "medium"),
        "event_type": rule.get("event_type"),
        "conditions": conditions,
        "mitre_tactic": tactic,
        "mitre_technique": technique,
        "pack_id": pack_id,
        "enabled": True,
        "organization_id": organization_id,
        "created_by": created_by,
        "created_at": now,
        "updated_at": now,
    }


async def seed_detection_packs(organization_id: str) -> None:
    for starter in STARTER_PACKS.values():
        now = utcnow()
        await detection_rule_packs_collection.update_one(
            {
                "organization_id": organization_id,
                "name": starter["name"],
                "version": starter["version"],
            },
            {
                "$set": {
                    "description": starter["description"],
                    "category": starter["category"],
                    "rules_count": len(starter["rules"]),
                    "enabled": True,
                    "updated_at": now,
                },
                "$setOnInsert": {
                    "name": starter["name"],
                    "version": starter["version"],
                    "organization_id": organization_id,
                    "created_by": DEMO_ADMIN_EMAIL,
                    "created_at": now,
                },
            },
            upsert=True,
        )
        pack = await detection_rule_packs_collection.find_one(
            {
                "organization_id": organization_id,
                "name": starter["name"],
                "version": starter["version"],
            }
        )
        pack_id = str(pack["_id"])
        for rule in starter["rules"]:
            document = sigma_rule_to_document(
                rule,
                pack_id=pack_id,
                organization_id=organization_id,
                created_by=DEMO_ADMIN_EMAIL,
            )
            created_at = document.pop("created_at")
            await detection_rules_collection.update_one(
                {"organization_id": organization_id, "name": document["name"]},
                {"$set": document, "$setOnInsert": {"created_at": created_at}},
                upsert=True,
            )

    custom_rules = [
        {
            "name": "Demo VPN impossible travel",
            "description": "Detect impossible travel VPN login pattern.",
            "severity": "high",
            "event_type": "vpn_login",
            "conditions": [{"field": "message", "operator": "contains", "value": "impossible travel"}],
            "mitre_tactic": "Credential Access",
            "mitre_technique": "T1078",
            "pack_id": None,
            "enabled": True,
            "organization_id": organization_id,
            "created_by": DEMO_ADMIN_EMAIL,
            "updated_at": utcnow(),
        }
    ]
    for rule in custom_rules:
        await detection_rules_collection.update_one(
            {"organization_id": organization_id, "name": rule["name"]},
            {"$set": rule, "$setOnInsert": {"created_at": utcnow()}},
            upsert=True,
        )


DEMO_EVENTS = [
    {
        "source": "demo-linux-agent",
        "event_type": "ssh_attack",
        "severity": "high",
        "message": "Multiple failed login attempts from external host",
        "ip_address": "203.0.113.44",
        "threat_score": 91,
        "threat_label": "malicious",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110",
        "matched_rule_name": "SSH failed login activity",
        "alert": True,
        "incident": True,
    },
    {
        "source": "demo-edr",
        "event_type": "malware",
        "severity": "critical",
        "message": "Endpoint process launched suspicious malware payload",
        "ip_address": "10.20.4.18",
        "threat_score": 97,
        "threat_label": "malicious",
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059",
        "matched_rule_name": "Suspicious malware execution",
        "alert": True,
        "incident": True,
    },
    {
        "source": "demo-fileserver",
        "event_type": "ransomware",
        "severity": "critical",
        "message": "Ransom note detected during suspicious bulk file encryption",
        "ip_address": "10.20.8.42",
        "threat_score": 99,
        "threat_label": "malicious",
        "mitre_tactic": "Impact",
        "mitre_technique": "T1486",
        "matched_rule_name": "Ransomware encryption activity",
        "alert": True,
        "incident": True,
    },
    {
        "source": "demo-firewall",
        "event_type": "network_scan",
        "severity": "medium",
        "message": "Suspicious outbound connection to newly registered domain",
        "ip_address": "198.51.100.23",
        "threat_score": 72,
        "threat_label": "suspicious",
        "mitre_tactic": "Command And Control",
        "mitre_technique": "T1071",
        "matched_rule_name": "Suspicious network connection",
        "alert": True,
        "incident": False,
    },
    {
        "source": "demo-identity",
        "event_type": "privilege_escalation",
        "severity": "high",
        "message": "VPN impossible travel login for finance user",
        "ip_address": "203.0.113.88",
        "threat_score": 85,
        "threat_label": "malicious",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1078",
        "matched_rule_name": "Privilege escalation attempt",
        "alert": True,
        "incident": True,
    },
    {
        "source": "demo-cloudtrail",
        "event_type": "cloud_audit",
        "severity": "low",
        "message": "Cloud configuration audit completed successfully",
        "ip_address": "10.20.2.7",
        "threat_score": 18,
        "threat_label": "benign",
        "mitre_tactic": "Unknown",
        "mitre_technique": "Unknown",
        "matched_rule_name": None,
        "alert": False,
        "incident": False,
    },
]


async def find_rule_id(organization_id: str, rule_name: str | None) -> str | None:
    if not rule_name:
        return None
    rule = await detection_rules_collection.find_one(
        {"organization_id": organization_id, "name": rule_name}
    )
    return str(rule["_id"]) if rule else None


async def seed_events(organization_id: str) -> None:
    base_time = utcnow() - timedelta(hours=3)
    for index, event in enumerate(DEMO_EVENTS):
        timestamp = base_time + timedelta(minutes=index * 24)
        rule_id = await find_rule_id(organization_id, event["matched_rule_name"])
        log_document = {
            "source": event["source"],
            "event_type": event["event_type"],
            "severity": event["severity"],
            "message": event["message"],
            "ip_address": event["ip_address"],
            "organization_id": organization_id,
            "threat_score": event["threat_score"],
            "threat_label": event["threat_label"],
            "mitre_tactic": event["mitre_tactic"],
            "mitre_technique": event["mitre_technique"],
            "ip_reputation": {"reputation": "demo", "source": "seed_demo"},
            "matched_rule_id": rule_id,
            "matched_rule_name": event["matched_rule_name"],
            "timestamp": timestamp,
            "demo_seed_key": f"demo-log-{index}",
        }
        await logs_collection.update_one(
            {"organization_id": organization_id, "demo_seed_key": log_document["demo_seed_key"]},
            {"$set": log_document},
            upsert=True,
        )
        log = await logs_collection.find_one(
            {"organization_id": organization_id, "demo_seed_key": log_document["demo_seed_key"]}
        )
        if not event["alert"]:
            continue

        alert_document = {
            "log_id": str(log["_id"]),
            "source": event["source"],
            "event_type": event["event_type"],
            "severity": event["severity"],
            "message": event["message"],
            "ip_address": event["ip_address"],
            "organization_id": organization_id,
            "threat_score": event["threat_score"],
            "threat_label": event["threat_label"],
            "mitre_tactic": event["mitre_tactic"],
            "mitre_technique": event["mitre_technique"],
            "ip_reputation": {"reputation": "demo", "source": "seed_demo"},
            "matched_rule_id": rule_id,
            "matched_rule_name": event["matched_rule_name"],
            "status": "open",
            "timestamp": timestamp + timedelta(seconds=10),
            "demo_seed_key": f"demo-alert-{index}",
        }
        await alerts_collection.update_one(
            {"organization_id": organization_id, "demo_seed_key": alert_document["demo_seed_key"]},
            {"$set": alert_document},
            upsert=True,
        )
        alert = await alerts_collection.find_one(
            {"organization_id": organization_id, "demo_seed_key": alert_document["demo_seed_key"]}
        )

        action_document = {
            "alert_id": str(alert["_id"]),
            "log_id": str(log["_id"]),
            "organization_id": organization_id,
            "event_type": event["event_type"],
            "severity": event["severity"],
            "ip_address": event["ip_address"],
            "automated_actions": [
                f"Blocked malicious IP: {event['ip_address']}",
                "Created investigation ticket",
                "Notified analyst channel",
            ],
            "blocked_ips": [event["ip_address"]],
            "status": "simulated",
            "timestamp": timestamp + timedelta(seconds=20),
            "demo_seed_key": f"demo-action-{index}",
        }
        await response_actions_collection.update_one(
            {
                "organization_id": organization_id,
                "demo_seed_key": action_document["demo_seed_key"],
            },
            {"$set": action_document},
            upsert=True,
        )

        if event["incident"]:
            incident_document = {
                "alert_id": str(alert["_id"]),
                "title": f"Demo {event['event_type']} incident",
                "description": event["message"],
                "severity": event["severity"],
                "status": "open" if index % 2 == 0 else "investigating",
                "assigned_to": DEMO_ANALYST_EMAIL,
                "created_by": DEMO_ADMIN_EMAIL,
                "organization_id": organization_id,
                "timestamp": timestamp + timedelta(seconds=30),
                "demo_seed_key": f"demo-incident-{index}",
            }
            await incidents_collection.update_one(
                {
                    "organization_id": organization_id,
                    "demo_seed_key": incident_document["demo_seed_key"],
                },
                {"$set": incident_document},
                upsert=True,
            )


async def seed_demo() -> None:
    await create_indexes()
    organization_id = await upsert_organization()
    await seed_users(organization_id)
    await seed_collectors(organization_id)
    await seed_detection_packs(organization_id)
    await seed_events(organization_id)
    print("Demo seed complete")
    print(f"organization={DEMO_ORG_NAME}")
    print(f"organization_id={organization_id}")
    print(f"admin={DEMO_ADMIN_EMAIL}")
    print(f"analyst={DEMO_ANALYST_EMAIL}")
    print(f"viewer={DEMO_VIEWER_EMAIL}")
    print(f"password={DEMO_ADMIN_PASSWORD}")
    print(f"collector_token={DEMO_COLLECTOR_TOKEN}")


async def main() -> None:
    try:
        await seed_demo()
    finally:
        await close_database()


if __name__ == "__main__":
    asyncio.run(main())
