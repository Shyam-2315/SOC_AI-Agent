MITRE_ATTACK_MAPPING = {

    "ssh_attack": {
        "tactic_id": "TA0006",
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access"
    },
    "linux_ssh_failed_login": {
        "tactic_id": "TA0006",
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access"
    },
    "windows_failed_login": {
        "tactic_id": "TA0006",
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access"
    },
    "linux_sudo_failure": {
        "tactic_id": "TA0004",
        "technique_id": "T1548.003",
        "technique_name": "Sudo and Sudo Caching",
        "tactic": "Privilege Escalation"
    },
    "windows_process_execution": {
        "tactic_id": "TA0002",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution"
    },
    "linux_suspicious_process": {
        "tactic_id": "TA0002",
        "technique_id": "T1059.004",
        "technique_name": "Unix Shell",
        "tactic": "Execution"
    },
    "syslog_event": {
        "tactic_id": "TA0007",
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "tactic": "Discovery"
    },

    "malware": {
        "tactic_id": "TA0002",
        "technique_id": "T1204",
        "technique_name": "User Execution",
        "tactic": "Execution"
    },

    "ransomware": {
        "tactic_id": "TA0040",
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "tactic": "Impact"
    },

    "network_activity": {
        "tactic_id": "TA0007",
        "technique_id": "T1046",
        "technique_name": "Network Service Scanning",
        "tactic": "Discovery"
    }
}


def map_to_mitre(event_type: str):

    if event_type in MITRE_ATTACK_MAPPING:

        return MITRE_ATTACK_MAPPING[event_type]

    return {
        "tactic_id": "Unknown",
        "technique_id": "Unknown",
        "technique_name": "Unknown",
        "tactic": "Unknown"
    }
