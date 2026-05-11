# backend/ai/threat_classifier.py

def classify_threat(
    event_type: str,
    severity: str,
    message: str
):

    severity = severity.lower()
    message = message.lower()

    high_risk_keywords = [
        "malware",
        "ransomware",
        "bruteforce",
        "phishing",
        "exploit",
        "attack"
    ]

    threat_score = 0

    # EVENT TYPE ANALYSIS
    if event_type.lower() in high_risk_keywords:

        threat_score += 50

    # SEVERITY ANALYSIS
    if severity == "critical":

        threat_score += 40

    elif severity == "high":

        threat_score += 30

    elif severity == "medium":

        threat_score += 20

    else:

        threat_score += 10

    # MESSAGE ANALYSIS
    for keyword in high_risk_keywords:

        if keyword in message:

            threat_score += 10

    # CLASSIFICATION
    if threat_score >= 70:

        label = "malicious"

    elif threat_score >= 40:

        label = "suspicious"

    else:

        label = "benign"

    return {

        "threat_score": threat_score,

        "label": label
    }