import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys


if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from app.db.client import alerts_collection, close_database
from app.db.client import organizations_collection
from app.services.attack_chain_service import generate_attack_chains


DEMO_ORGANIZATION_NAME = "Demo SOC"


async def demo_organization_id() -> str:
    organization = await organizations_collection.find_one({"name": DEMO_ORGANIZATION_NAME})
    if organization is not None:
        return str(organization["_id"])
    result = await organizations_collection.insert_one({
        "name": DEMO_ORGANIZATION_NAME,
        "created_by": "attack-chain-demo",
        "created_at": datetime.now(timezone.utc),
    })
    return str(result.inserted_id)


def demo_alerts(organization_id: str) -> list[dict]:
    now = datetime.now(timezone.utc)
    base = {
        "organization_id": organization_id,
        "source": "attack-chain-demo",
        "hostname": "win-workstation-01",
        "host": "win-workstation-01",
        "username": "alice",
        "source_ip": "203.0.113.10",
        "destination_ip": "10.0.4.25",
        "status": "open",
    }
    return [
        {
            **base,
            "title": "Suspicious remote login",
            "event_type": "suspicious_login",
            "severity": "high",
            "message": "Suspicious login for alice from 203.0.113.10.",
            "timestamp": now - timedelta(minutes=45),
        },
        {
            **base,
            "title": "PowerShell EncodedCommand execution",
            "event_type": "process_execution",
            "severity": "high",
            "message": "PowerShell launched with EncodedCommand after login.",
            "process_name": "powershell.exe",
            "timestamp": now - timedelta(minutes=38),
        },
        {
            **base,
            "title": "Credential dump from LSASS",
            "event_type": "credential_dumping",
            "severity": "critical",
            "message": "Mimikatz behavior and LSASS access consistent with credential dump.",
            "process_name": "mimikatz.exe",
            "timestamp": now - timedelta(minutes=31),
        },
        {
            **base,
            "title": "SSH remote login lateral movement",
            "event_type": "lateral_movement",
            "severity": "critical",
            "message": "SSH remote login from compromised workstation to linux-app-02.",
            "destination_ip": "10.0.8.44",
            "timestamp": now - timedelta(minutes=18),
        },
        {
            **base,
            "title": "Large outbound data upload",
            "event_type": "data_exfiltration",
            "severity": "critical",
            "message": "Large outbound transfer indicates possible data exfiltration.",
            "destination_ip": "198.51.100.50",
            "timestamp": now - timedelta(minutes=8),
        },
    ]


async def main() -> None:
    organization_id = await demo_organization_id()
    await alerts_collection.insert_many(demo_alerts(organization_id))
    result = await generate_attack_chains(organization_id, lookback_hours=24)
    print(f"Inserted demo alerts for organization_id={organization_id}")
    print(f"Generated {result['generated']} attack chain(s)")
    for chain in result["items"]:
        print(f"- {chain['id']} {chain['title']} risk={chain['risk_score']}/10")
    await close_database()


if __name__ == "__main__":
    asyncio.run(main())
