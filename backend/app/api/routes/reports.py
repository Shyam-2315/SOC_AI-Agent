from fastapi import APIRouter, Depends, Query

from app.api.dependencies import require_permission
from app.schemas.reports import IncidentReport, IncidentReportResponse, ReportType
from app.services.report_generator_service import (
    generate_compliance_report,
    generate_executive_report,
    generate_incident_report,
    generate_technical_report,
)


router = APIRouter(prefix="/api/reports", tags=["Reports"])


@router.get("/incidents/{incident_id}", response_model=IncidentReportResponse)
async def generate_incident_report_endpoint(
    incident_id: str,
    report_type: ReportType = Query(default="technical"),
    user=Depends(require_permission("incidents:read")),
):
    report = await generate_incident_report(
        incident_id,
        report_type,
        user["organization_id"],
    )
    return {"report": report}


@router.get("/incidents/{incident_id}/executive", response_model=IncidentReportResponse)
async def generate_executive_report_endpoint(
    incident_id: str,
    user=Depends(require_permission("incidents:read")),
):
    report = await generate_executive_report(incident_id, user["organization_id"])
    return {"report": report}


@router.get("/incidents/{incident_id}/technical", response_model=IncidentReportResponse)
async def generate_technical_report_endpoint(
    incident_id: str,
    user=Depends(require_permission("incidents:read")),
):
    report = await generate_technical_report(incident_id, user["organization_id"])
    return {"report": report}


@router.get("/incidents/{incident_id}/compliance", response_model=IncidentReportResponse)
async def generate_compliance_report_endpoint(
    incident_id: str,
    user=Depends(require_permission("incidents:read")),
):
    report = await generate_compliance_report(incident_id, user["organization_id"])
    return {"report": report}


@router.get("/incidents/{incident_id}/json", response_model=IncidentReport)
async def generate_incident_report_json_endpoint(
    incident_id: str,
    report_type: ReportType = Query(default="technical"),
    user=Depends(require_permission("incidents:read")),
):
    return await generate_incident_report(
        incident_id,
        report_type,
        user["organization_id"],
    )
