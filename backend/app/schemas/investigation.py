from datetime import datetime
from typing import Any, List

from pydantic import BaseModel

from app.models.security import DetectionSeverity


class InvestigationSchema(BaseModel):
    investigation_id: str
    upload_id: str
    source_ip: str
    incident_type: str
    severity: DetectionSeverity
    risk_score: int
    attack_chain: List[str]
    detections: List[Any]
    mitre_techniques: List[str]
    generated_at: datetime
