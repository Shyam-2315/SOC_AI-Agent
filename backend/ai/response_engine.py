BLOCKED_IPS = []


def generate_response(alert_data: dict):

    actions = []

    severity = alert_data.get("severity")

    ip_address = alert_data.get("ip_address")

    event_type = alert_data.get("event_type")

    # AUTO BLOCK MALICIOUS IPS
    if severity == "Critical":

        if ip_address not in BLOCKED_IPS:

            BLOCKED_IPS.append(ip_address)

            actions.append(
                f"Blocked malicious IP: {ip_address}"
            )

    # SSH RESPONSE
    if event_type == "ssh_attack":

        actions.append(
            "Disable SSH password authentication"
        )

        actions.append(
            "Enable fail2ban protection"
        )

    # MALWARE RESPONSE
    if event_type == "malware":

        actions.append(
            "Isolate infected endpoint"
        )

        actions.append(
            "Run antivirus scan"
        )

    # RANSOMWARE RESPONSE
    if event_type == "ransomware":

        actions.append(
            "Disconnect host from network"
        )

        actions.append(
            "Trigger backup recovery protocol"
        )

    # NETWORK THREAT RESPONSE
    if event_type == "network_activity":

        actions.append(
            "Initiate network traffic inspection"
        )

        actions.append(
            "Block suspicious outbound traffic"
        )

    return {
        "automated_actions": actions,
        "blocked_ips": BLOCKED_IPS
    }