"""Pydantic schemas for AI-generated security reports."""

from datetime import datetime
from typing import List

from pydantic import BaseModel, Field


class SecurityReportSchema(BaseModel):
    report_id: str
    upload_id: str
    source_ip: str
    severity: str
    risk_score: int
    executive_summary: str
    attack_narrative: str
    business_impact: str
    mitre_analysis: str
    recommended_actions: List[str] = Field(default_factory=list)
    generated_at: datetime


class ReportGenerateResponse(BaseModel):
    report_id: str
    upload_id: str
    severity: str
    risk_score: int


class GeminiReportContent(BaseModel):
    executive_summary: str = ""
    attack_narrative: str = ""
    mitre_analysis: str = ""
    business_impact: str = ""
    recommended_actions: List[str] = Field(default_factory=list)
