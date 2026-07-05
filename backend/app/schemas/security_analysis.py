from datetime import datetime
from typing import List

from pydantic import BaseModel

from app.schemas.detections import DetectionSchema
from app.schemas.investigation import InvestigationSchema
from app.schemas.risk import RiskAssessmentSchema



class TimelineSchema(BaseModel):
    attack_chain: List[str]



class AnomalyDetectionSchema(BaseModel):
    anomaly_score: int
    is_anomalous: bool



class SecurityAnalysisResponse(BaseModel):
    upload_id: str
    detections: List[DetectionSchema]
    risk_assessment: RiskAssessmentSchema
    timeline: TimelineSchema
    investigation: InvestigationSchema
    anomaly_detection: AnomalyDetectionSchema



class SecurityAnalysisSummaryResponse(BaseModel):
    upload_id: str
    risk_score: int
    severity: str
    detection_count: int
    investigation_id: str

