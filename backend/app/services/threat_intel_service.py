from datetime import datetime, timezone
from ipaddress import ip_address
import re
from typing import Any
from urllib.parse import urlparse

from fastapi import HTTPException

from app.common.mongo import parse_object_id, serialize_document
from app.db.client import alerts_collection, incidents_collection


NOW = datetime(2026, 6, 3, tzinfo=timezone.utc).isoformat()

DEMO_FEED: list[dict[str, Any]] = [
    {
        "indicator": "203.0.113.10",
        "type": "ip",
        "reputation_score": 95,
        "verdict": "malicious",
        "source": "demo_feed",
        "tags": ["brute_force", "credential_access", "demo"],
        "first_seen": "2026-05-01T00:00:00+00:00",
        "last_seen": NOW,
        "description": "Demo brute-force source IP observed in repeated failed-login activity.",
        "confidence": 0.92,
    },
    {
        "indicator": "198.51.100.23",
        "type": "ip",
        "reputation_score": 88,
        "verdict": "malicious",
        "source": "demo_feed",
        "tags": ["dos", "scanner", "demo"],
        "first_seen": "2026-05-04T00:00:00+00:00",
        "last_seen": NOW,
        "description": "Demo DoS source IP used in traffic spike simulations.",
        "confidence": 0.86,
    },
    {
        "indicator": "evil.example",
        "type": "domain",
        "reputation_score": 82,
        "verdict": "malicious",
        "source": "demo_feed",
        "tags": ["phishing", "c2", "demo"],
        "first_seen": "2026-04-20T00:00:00+00:00",
        "last_seen": NOW,
        "description": "Demo malicious domain used for phishing and callback examples.",
        "confidence": 0.9,
    },
    {
        "indicator": "suspicious-login.example",
        "type": "domain",
        "reputation_score": 64,
        "verdict": "suspicious",
        "source": "demo_feed",
        "tags": ["credential_harvest", "demo"],
        "first_seen": "2026-05-10T00:00:00+00:00",
        "last_seen": NOW,
        "description": "Demo suspicious domain resembling a login portal.",
        "confidence": 0.72,
    },
    {
        "indicator": "https://phish.example/login",
        "type": "url",
        "reputation_score": 91,
        "verdict": "malicious",
        "source": "demo_feed",
        "tags": ["phishing", "credential_harvest", "demo"],
        "first_seen": "2026-05-12T00:00:00+00:00",
        "last_seen": NOW,
        "description": "Demo phishing URL for credential collection workflows.",
        "confidence": 0.88,
    },
    {
        "indicator": "44d88612fea8a8f36de82e1278abb02f",
        "type": "hash",
        "reputation_score": 97,
        "verdict": "malicious",
        "source": "demo_feed",
        "tags": ["malware", "eicar_style", "demo"],
        "first_seen": "2026-04-15T00:00:00+00:00",
        "last_seen": NOW,
        "description": "Demo malware hash used for deterministic enrichment.",
        "confidence": 0.95,
    },
    {
        "indicator": "attacker@evil.example",
        "type": "email",
        "reputation_score": 76,
        "verdict": "suspicious",
        "source": "demo_feed",
        "tags": ["phishing", "sender", "demo"],
        "first_seen": "2026-05-17T00:00:00+00:00",
        "last_seen": NOW,
        "description": "Demo suspicious sender used in phishing simulations.",
        "confidence": 0.78,
    },
    {
        "indicator": "8.8.8.8",
        "type": "ip",
        "reputation_score": 5,
        "verdict": "clean",
        "source": "internal",
        "tags": ["resolver", "baseline"],
        "first_seen": "2026-05-01T00:00:00+00:00",
        "last_seen": NOW,
        "description": "Known public resolver included as a clean deterministic baseline.",
        "confidence": 0.8,
    },
]

IOC_FIELDS = [
    "source_ip",
    "destination_ip",
    "ip",
    "ip_address",
    "domain",
    "url",
    "file_hash",
    "hash",
    "email",
]


def _feed_index() -> dict[tuple[str, str], dict[str, Any]]:
    index = {}
    for item in DEMO_FEED:
        normalized, indicator_type = normalize_indicator(item["indicator"], item["type"])
        index[(indicator_type, normalized)] = item
        if indicator_type == "url":
            domain = extract_domain(normalized)
            if domain:
                index.setdefault(("domain", domain), item)
    return index


def get_feed() -> dict:
    return {"items": [dict(item) for item in DEMO_FEED]}


def lookup_ioc(indicator: str) -> dict:
    normalized, indicator_type = normalize_indicator(indicator)
    match = _feed_index().get((indicator_type, normalized))
    if not match and indicator_type == "url":
        domain = extract_domain(normalized)
        if domain:
            match = _feed_index().get(("domain", domain))
    if match:
        return {
            **match,
            "indicator": indicator,
            "normalized_indicator": normalized,
            "explanation": f"Matched {match['type']} indicator in {match['source']} feed.",
        }
    return {
        "indicator": indicator,
        "normalized_indicator": normalized,
        "type": indicator_type,
        "reputation_score": 0,
        "verdict": "unknown",
        "source": None,
        "tags": [],
        "first_seen": None,
        "last_seen": None,
        "description": None,
        "confidence": 0,
        "explanation": "Indicator was not present in deterministic internal threat intelligence.",
    }


def bulk_lookup_iocs(indicators: list[str]) -> dict:
    return {"items": [lookup_ioc(indicator) for indicator in indicators]}


async def enrich_alert_threat_intel(alert_id: str, organization_id: str) -> dict:
    object_id = parse_object_id(alert_id, "alert")
    alert = await alerts_collection.find_one({"_id": object_id, "organization_id": organization_id})
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return enrich_alert_document(serialize_document(alert))


async def enrich_incident_threat_intel(incident_id: str, organization_id: str) -> dict:
    object_id = parse_object_id(incident_id, "incident")
    incident = await incidents_collection.find_one(
        {"_id": object_id, "organization_id": organization_id}
    )
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    serialized = serialize_document(incident)
    alerts = await _incident_alerts(serialized, organization_id)
    enrichments = [enrich_alert_document(alert) for alert in alerts]
    matched = _dedupe_matches(
        match for enrichment in enrichments for match in enrichment["matched_iocs"]
    )
    affected_assets = sorted(
        {
            str(value)
            for alert in alerts
            for value in (alert.get("hostname"), alert.get("host"), alert.get("source"))
            if value
        }
    )
    malicious_source_ips = sorted(
        {
            match["normalized_indicator"]
            for match in matched
            if match.get("type") == "ip" and match.get("verdict") == "malicious"
        }
    )
    suspicious_domains = sorted(
        {
            match["normalized_indicator"]
            for match in matched
            if match.get("type") == "domain" and match.get("verdict") in {"suspicious", "malicious"}
        }
    )
    highest_risk = max((int(match["reputation_score"]) for match in matched), default=0)
    actions = []
    if malicious_source_ips:
        actions.append("block_ip")
    if highest_risk >= 80:
        actions.append("open_investigation")
        actions.append("run_threat_hunt")
    if suspicious_domains:
        actions.append("run_threat_hunt")
    if not actions:
        actions.append("monitor_only")
    return {
        "incident_id": str(serialized.get("_id") or incident_id),
        "matched_indicators": matched,
        "affected_assets": affected_assets,
        "malicious_source_ips": malicious_source_ips,
        "suspicious_domains": suspicious_domains,
        "highest_risk": highest_risk,
        "recommended_actions": list(dict.fromkeys(actions)),
    }


def enrich_alert_document(alert: dict[str, Any]) -> dict:
    indicators = extract_indicators(alert)
    matches = [lookup_ioc(indicator) for indicator in indicators]
    matched_iocs = [match for match in matches if match["verdict"] != "unknown"]
    matched_iocs = _dedupe_matches(matched_iocs)
    highest = max((int(match["reputation_score"]) for match in matched_iocs), default=0)
    verdict = _combined_verdict(matched_iocs)
    explanations = [
        f"{match['normalized_indicator']} is {match['verdict']} ({match['reputation_score']})."
        for match in matched_iocs
    ]
    if not explanations:
        explanations.append("No known malicious or suspicious indicators were found.")
    return {
        "matched_iocs": matched_iocs,
        "highest_reputation_score": highest,
        "threat_verdict": verdict,
        "recommended_action": _recommended_action(verdict, highest),
        "explanation": explanations,
    }


def extract_indicators(document: dict[str, Any]) -> list[str]:
    values = []
    for field in IOC_FIELDS:
        value = document.get(field)
        if value:
            values.append(str(value))
    raw = " ".join(str(document.get(field) or "") for field in ("message", "description", "raw"))
    values.extend(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw))
    values.extend(re.findall(r"\b[a-fA-F0-9]{32,64}\b", raw))
    values.extend(re.findall(r"https?://[^\s'\"]+", raw))
    values.extend(re.findall(r"\b[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}\b", raw))
    return list(dict.fromkeys(value.strip() for value in values if value and value.strip()))


def normalize_indicator(indicator: str, expected_type: str | None = None) -> tuple[str, str]:
    value = indicator.strip().strip(".,;()[]{}'\"")
    lowered = value.lower()
    if expected_type == "ip" or _is_ip(lowered):
        return str(ip_address(lowered)), "ip"
    if expected_type == "url" or lowered.startswith(("http://", "https://")):
        parsed = urlparse(lowered)
        normalized_url = lowered.rstrip("/")
        if parsed.scheme and parsed.netloc:
            return normalized_url, "url"
    if expected_type == "email" or re.fullmatch(r"[\w.+-]+@[\w.-]+\.[a-z]{2,}", lowered):
        return lowered, "email"
    if expected_type == "hash" or re.fullmatch(r"[a-f0-9]{32,64}", lowered):
        return lowered, "hash"
    if expected_type == "domain" or re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", lowered):
        return lowered, "domain"
    return lowered, expected_type or "domain"


def extract_domain(indicator: str) -> str | None:
    parsed = urlparse(indicator)
    if parsed.netloc:
        return parsed.netloc.lower()
    if re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", indicator.lower()):
        return indicator.lower()
    return None


async def _incident_alerts(incident: dict[str, Any], organization_id: str) -> list[dict[str, Any]]:
    alert_ids = []
    if incident.get("alert_id"):
        alert_ids.append(str(incident["alert_id"]))
    alert_ids.extend(str(alert_id) for alert_id in incident.get("related_alert_ids", []))
    existing = [alert for alert in incident.get("related_alerts", []) if isinstance(alert, dict)]
    seen = {str(alert.get("_id") or alert.get("id")) for alert in existing}
    wanted = set(alert_ids) - seen
    alerts = [serialize_document(alert) for alert in existing]
    if wanted:
        cursor = alerts_collection.find({"organization_id": organization_id}).sort("timestamp", -1)
        async for alert in cursor:
            serialized = serialize_document(alert)
            if str(serialized.get("_id") or serialized.get("id")) in wanted:
                alerts.append(serialized)
    return alerts


def _combined_verdict(matches: list[dict[str, Any]]) -> str:
    verdicts = {match["verdict"] for match in matches}
    if "malicious" in verdicts:
        return "malicious"
    if "suspicious" in verdicts:
        return "suspicious"
    if "clean" in verdicts:
        return "clean"
    return "unknown"


def _recommended_action(verdict: str, score: int) -> str:
    if verdict == "malicious" and score >= 80:
        return "block_ip_or_open_investigation"
    if verdict in {"malicious", "suspicious"}:
        return "run_threat_hunt"
    if verdict == "clean":
        return "monitor_only"
    return "investigate"


def _dedupe_matches(matches) -> list[dict[str, Any]]:
    deduped = {}
    for match in matches:
        key = (match.get("type"), match.get("normalized_indicator"))
        deduped[key] = match
    return list(deduped.values())


def _is_ip(value: str) -> bool:
    try:
        ip_address(value)
        return True
    except ValueError:
        return False
