from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.models.security import DetectionSeverity


class DetectionSchema(BaseModel):
    detection_id: str
    upload_id: str
    source_ip: str
    detection_type: str
    severity: DetectionSeverity
    confidence: float = Field(default=1.0)
    details: dict[str, Any] = Field(default_factory=dict)
    generated_at: datetime
