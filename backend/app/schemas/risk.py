from datetime import datetime
from typing import List

from pydantic import BaseModel

from app.models.security import DetectionSeverity


class RiskAssessmentSchema(BaseModel):
    risk_id: str
    upload_id: str
    source_ip: str
    score: int
    severity: DetectionSeverity
    detection_types: List[str]
    generated_at: datetime
