"""Pydantic schemas for AI-generated security reports."""

from datetime import datetime
from typing import List

from pydantic import BaseModel, Field


class AttackChainPhaseSchema(BaseModel):
    name: str
    detections: List[str] = Field(default_factory=list)
    mitre: List[str] = Field(default_factory=list)
    evidence: dict[str, List[str]] = Field(default_factory=dict)


class ReportMetadataSchema(BaseModel):
    severity: str = ""
    risk_score: int = 0
    confidence: float = 0.0
    detection_count: int = 0
    correlated_event_count: int = 0
    affected_hosts: List[str] = Field(default_factory=list)
    affected_accounts: List[str] = Field(default_factory=list)
    time_window: str = ""
    mitre_techniques_observed: List[str] = Field(default_factory=list)


class ReportIocsSchema(BaseModel):
    external_ips: List[str] = Field(default_factory=list)
    internal_ips: List[str] = Field(default_factory=list)
    hosts: List[str] = Field(default_factory=list)
    accounts: List[str] = Field(default_factory=list)
    processes: List[str] = Field(default_factory=list)
    commands: List[str] = Field(default_factory=list)
    files: List[str] = Field(default_factory=list)
    registry_keys: List[str] = Field(default_factory=list)
    cron_jobs: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)
    hashes: List[str] = Field(default_factory=list)


class MitreTableEntrySchema(BaseModel):
    technique: str
    mitre_id: str
    evidence: str
    source_detection: str


class RecommendationsSchema(BaseModel):
    immediate_containment: List[str] = Field(default_factory=list)
    investigation: List[str] = Field(default_factory=list)
    recovery: List[str] = Field(default_factory=list)
    hardening: List[str] = Field(default_factory=list)


class SecurityReportSchema(BaseModel):
    report_id: str
    upload_id: str
    source_ip: str
    severity: str
    risk_score: int
    executive_summary: str
    executive_narrative: str = ""
    attack_narrative: str
    business_impact: str
    business_impact_details: dict[str, List[str]] = Field(default_factory=dict)
    mitre_analysis: str
    recommended_actions: List[str] = Field(default_factory=list)
    attack_chain: List[AttackChainPhaseSchema] = Field(default_factory=list)
    metadata: ReportMetadataSchema = Field(default_factory=ReportMetadataSchema)
    iocs: ReportIocsSchema = Field(default_factory=ReportIocsSchema)
    mitre_table: List[MitreTableEntrySchema] = Field(default_factory=list)
    recommendations: RecommendationsSchema = Field(default_factory=RecommendationsSchema)
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
