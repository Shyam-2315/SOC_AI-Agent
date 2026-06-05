from fastapi import APIRouter, Depends, Query

from app.api.dependencies import require_permission
from app.schemas.threat_intel import (
    BulkThreatIntelLookupRequest,
    BulkThreatIntelLookupResponse,
    IncidentThreatIntelEnrichmentResponse,
    ThreatIntelEnrichmentResponse,
    ThreatIntelFeedResponse,
    ThreatIntelLookupResponse,
)
from app.services.threat_intel_service import (
    bulk_lookup_iocs,
    enrich_alert_threat_intel,
    enrich_incident_threat_intel,
    get_feed,
    lookup_ioc,
)


router = APIRouter(prefix="/api/threat-intel", tags=["Threat Intelligence"])
alias_router = APIRouter(
    prefix="/threat-intel",
    tags=["Threat Intelligence"],
    include_in_schema=False,
)


@alias_router.get("/lookup", response_model=ThreatIntelLookupResponse)
@router.get("/lookup", response_model=ThreatIntelLookupResponse)
async def lookup_threat_intel(
    indicator: str = Query(min_length=1, max_length=500),
    user=Depends(require_permission("threat_intel:read")),
):
    _ = user
    return lookup_ioc(indicator)


@alias_router.post("/bulk-lookup", response_model=BulkThreatIntelLookupResponse)
@router.post("/bulk-lookup", response_model=BulkThreatIntelLookupResponse)
async def bulk_lookup_threat_intel(
    payload: BulkThreatIntelLookupRequest,
    user=Depends(require_permission("threat_intel:read")),
):
    _ = user
    return bulk_lookup_iocs(payload.indicators)


@alias_router.get("/", response_model=ThreatIntelFeedResponse)
@alias_router.get("/feed", response_model=ThreatIntelFeedResponse)
@router.get("/feed", response_model=ThreatIntelFeedResponse)
async def threat_intel_feed(
    user=Depends(require_permission("threat_intel:read")),
):
    _ = user
    return get_feed()


@alias_router.post("/enrich-alert/{alert_id}", response_model=ThreatIntelEnrichmentResponse)
@router.post("/enrich-alert/{alert_id}", response_model=ThreatIntelEnrichmentResponse)
async def enrich_alert_endpoint(
    alert_id: str,
    user=Depends(require_permission("alerts:read")),
):
    return await enrich_alert_threat_intel(alert_id, user["organization_id"])


@router.post(
    "/enrich-incident/{incident_id}",
    response_model=IncidentThreatIntelEnrichmentResponse,
)
@alias_router.post(
    "/enrich-incident/{incident_id}",
    response_model=IncidentThreatIntelEnrichmentResponse,
)
async def enrich_incident_endpoint(
    incident_id: str,
    user=Depends(require_permission("incidents:read")),
):
    return await enrich_incident_threat_intel(incident_id, user["organization_id"])
