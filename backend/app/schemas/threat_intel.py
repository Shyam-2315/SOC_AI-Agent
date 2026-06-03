from typing import Literal

from pydantic import Field

from app.schemas.base import APIModel


IOCType = Literal["ip", "domain", "url", "hash", "email"]
ThreatVerdict = Literal["clean", "suspicious", "malicious", "unknown"]
ThreatSource = Literal["internal", "demo_feed", "imported"]


class ThreatIntelRecord(APIModel):
    indicator: str
    type: IOCType
    reputation_score: int = Field(ge=0, le=100)
    verdict: ThreatVerdict
    source: ThreatSource
    tags: list[str] = []
    first_seen: str | None = None
    last_seen: str | None = None
    description: str | None = None
    confidence: float = Field(ge=0, le=1)


class ThreatIntelLookupResponse(APIModel):
    indicator: str
    normalized_indicator: str
    type: IOCType | None = None
    reputation_score: int = Field(ge=0, le=100)
    verdict: ThreatVerdict
    source: ThreatSource | None = None
    tags: list[str] = []
    first_seen: str | None = None
    last_seen: str | None = None
    description: str | None = None
    confidence: float = Field(ge=0, le=1)
    explanation: str


class BulkThreatIntelLookupRequest(APIModel):
    indicators: list[str] = Field(min_length=1, max_length=100)


class BulkThreatIntelLookupResponse(APIModel):
    items: list[ThreatIntelLookupResponse]


class ThreatIntelFeedResponse(APIModel):
    items: list[ThreatIntelRecord]


class ThreatIntelEnrichmentResponse(APIModel):
    matched_iocs: list[ThreatIntelLookupResponse]
    highest_reputation_score: int = Field(ge=0, le=100)
    threat_verdict: ThreatVerdict
    recommended_action: str
    explanation: list[str]


class IncidentThreatIntelEnrichmentResponse(APIModel):
    incident_id: str
    matched_indicators: list[ThreatIntelLookupResponse]
    affected_assets: list[str]
    malicious_source_ips: list[str]
    suspicious_domains: list[str]
    highest_risk: int = Field(ge=0, le=100)
    recommended_actions: list[str]
