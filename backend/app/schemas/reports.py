from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from app.schemas.base import APIModel


ReportType = Literal["executive", "technical", "compliance"]


class ReportSection(APIModel):
    title: str = Field(min_length=1, max_length=120)
    summary: str = Field(min_length=1, max_length=2000)
    items: list[str] = Field(default_factory=list)
    data: dict[str, Any] = Field(default_factory=dict)


class IncidentReport(APIModel):
    incident_id: str
    report_type: ReportType
    title: str = Field(min_length=1, max_length=180)
    generated_at: datetime
    executive_summary: str
    severity: str
    affected_assets: list[str]
    timeline: list[dict[str, Any]]
    mitre_techniques: list[dict[str, Any]]
    matched_iocs: list[dict[str, Any]]
    recommended_actions: list[str]
    soar_actions: list[dict[str, Any]]
    analyst_notes: str
    sections: list[ReportSection]


class IncidentReportRequest(APIModel):
    incident_id: str = Field(min_length=1)
    report_type: ReportType


class IncidentReportResponse(APIModel):
    report: IncidentReport
