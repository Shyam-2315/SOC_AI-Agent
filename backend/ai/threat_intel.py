MALICIOUS_IPS = [
    "192.168.1.99",
    "45.33.32.156",
    "185.220.101.1",
    "103.25.58.1"
]


def check_ip_reputation(ip_address: str):

    if ip_address in MALICIOUS_IPS:

        return {
            "malicious": True,
            "threat_source": "Known Threat Feed",
            "confidence": "High"
        }

    return {
        "malicious": False,
        "threat_source": None,
        "confidence": "Low"
    }