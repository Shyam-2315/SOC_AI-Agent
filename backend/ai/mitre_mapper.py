MITRE_ATTACK_MAPPING = {

    "ssh_attack": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access"
    },

    "malware": {
        "technique_id": "T1204",
        "technique_name": "User Execution",
        "tactic": "Execution"
    },

    "ransomware": {
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "tactic": "Impact"
    },

    "network_activity": {
        "technique_id": "T1046",
        "technique_name": "Network Service Scanning",
        "tactic": "Discovery"
    }
}


def map_to_mitre(event_type: str):

    if event_type in MITRE_ATTACK_MAPPING:

        return MITRE_ATTACK_MAPPING[event_type]

    return {
        "technique_id": "Unknown",
        "technique_name": "Unknown",
        "tactic": "Unknown"
    }