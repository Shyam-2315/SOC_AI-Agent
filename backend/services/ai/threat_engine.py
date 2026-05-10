def classify_threat(event_type: str, message: str):

    severity = "Low"

    message_lower = message.lower()

    if "failed" in message_lower:
        severity = "Medium"

    if "brute force" in message_lower:
        severity = "High"

    if "malware" in message_lower:
        severity = "Critical"

    return {
        "severity": severity
    }