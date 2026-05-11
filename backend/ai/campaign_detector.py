from app.db.client import alerts_collection


async def detect_attack_campaign(
    ip_address: str,
    organization_id: str,
):

    related_alerts = []

    async for alert in alerts_collection.find({
        "ip_address": ip_address,
        "organization_id": organization_id,
    }):

        related_alerts.append(alert)

    event_types = [
        alert.get("event_type")
        for alert in related_alerts
    ]

    campaign_detected = False
    campaign_name = None

    if (
        "network_scan" in event_types
        and "ssh_attack" in event_types
        and "malware" in event_types
    ):

        campaign_detected = True
        campaign_name = "Multi-Stage Intrusion Campaign"

    elif (
        "ssh_attack" in event_types
        and "privilege_escalation" in event_types
        and "ransomware" in event_types
    ):

        campaign_detected = True
        campaign_name = "Ransomware Attack Chain"

    elif (
        "phishing" in event_types
        and "credential_access" in event_types
        and "lateral_movement" in event_types
    ):

        campaign_detected = True
        campaign_name = "Credential Compromise Campaign"

    return {
        "campaign_detected": campaign_detected,
        "campaign_name": campaign_name,
        "related_alert_count": len(related_alerts),
        "related_events": event_types
    }
