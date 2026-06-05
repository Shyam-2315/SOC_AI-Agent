from typing import Any


MITRE_RULES = [
    {
        "keywords": ("powershell", "cmd.exe", "bash", "shell", "script", "encodedcommand"),
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
    },
    {
        "keywords": ("mimikatz", "lsass", "credential dump", "hash dump", "credential dumping"),
        "technique_id": "T1003",
        "technique_name": "OS Credential Dumping",
        "tactic": "Credential Access",
    },
    {
        "keywords": ("rdp", "ssh", "smb", "winrm", "lateral movement", "remote login"),
        "technique_id": "T1021",
        "technique_name": "Remote Services",
        "tactic": "Lateral Movement",
    },
    {
        "keywords": ("scheduled task", "cron", "startup folder"),
        "technique_id": "T1053",
        "technique_name": "Scheduled Task/Job",
        "tactic": "Execution/Persistence/Privilege Escalation",
    },
    {
        "keywords": ("data upload", "exfiltration", "large outbound transfer"),
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
    },
    {
        "keywords": ("suspicious download", "payload download", "curl", "wget"),
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
    },
]


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _alert_text(alert: dict[str, Any]) -> str:
    values = []
    for key in (
        "title",
        "event_type",
        "message",
        "source",
        "process_name",
        "command_line",
        "raw_event",
        "mitre_technique",
        "mitre_technique_id",
        "mitre_technique_name",
    ):
        values.append(_text(alert.get(key)))
    return " ".join(values).lower()


def map_alert_to_mitre(alert: dict[str, Any]) -> list[dict[str, str]]:
    text = _alert_text(alert)
    mappings = []
    seen = set()

    existing_id = _text(alert.get("mitre_technique_id")).upper()
    existing_name = _text(alert.get("mitre_technique_name") or alert.get("mitre_technique"))
    existing_tactic = _text(alert.get("mitre_tactic_name") or alert.get("mitre_tactic"))
    if existing_id and existing_id != "UNKNOWN":
        mappings.append(
            {
                "technique_id": existing_id,
                "technique_name": existing_name or existing_id,
                "tactic": existing_tactic or "Unknown",
                "reason": "Existing MITRE fields on the alert.",
            }
        )
        seen.add(existing_id)

    for rule in MITRE_RULES:
        matched_keyword = next((keyword for keyword in rule["keywords"] if keyword in text), None)
        if not matched_keyword or rule["technique_id"] in seen:
            continue
        mappings.append(
            {
                "technique_id": rule["technique_id"],
                "technique_name": rule["technique_name"],
                "tactic": rule["tactic"],
                "reason": f"Matched keyword '{matched_keyword}' in alert context.",
            }
        )
        seen.add(rule["technique_id"])

    return mappings
