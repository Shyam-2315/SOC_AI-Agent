ATTACK_PATTERNS = {

    (
        "network_scan",
        "ssh_attack",
        "malware"
    ): "Multi-Stage Intrusion Campaign",

    (
        "ssh_attack",
        "privilege_escalation",
        "ransomware"
    ): "Ransomware Attack Chain",

    (
        "phishing",
        "credential_access",
        "lateral_movement"
    ): "Credential Compromise Campaign"
}


def correlate_events(alerts):

    detected_campaigns = []

    event_sequence = []

    for alert in alerts:

        event_sequence.append(
            alert.get("event_type")
        )

    for pattern, campaign_name in ATTACK_PATTERNS.items():

        matched = all(
            event in event_sequence
            for event in pattern
        )

        if matched:

            detected_campaigns.append({

                "campaign": campaign_name,

                "matched_events": list(pattern),

                "severity": "Critical"
            })

    return detected_campaigns
