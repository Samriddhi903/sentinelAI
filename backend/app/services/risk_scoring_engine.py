from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from pydantic import BaseModel, Field

from app.models.security import DetectionSeverity
from app.models.security_catalog import SECURITY_RULE_CATALOG
from app.services.detection_engine import Detection


class RiskAssessment(BaseModel):
    risk_id: str = Field(default_factory=lambda: str(uuid4()))
    upload_id: str
    source_ip: str
    score: int
    severity: DetectionSeverity
    detection_types: list[str]
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class RiskScoringEngine:
    WEIGHTS: dict[str, int] = {
        detection_type: metadata.risk_weight
        for detection_type, metadata in SECURITY_RULE_CATALOG.items()
    }

    def score_detections(self, detections: list[Detection]) -> RiskAssessment:
        detection_types = [d.detection_type for d in detections]
        unique_types = list(dict.fromkeys(detection_types))
        total_score = sum(self.WEIGHTS.get(detection_type, 0) for detection_type in unique_types)
        total_score = min(total_score, 100)
        severity = self._severity_for_score(total_score)

        if detections:
            upload_id = detections[0].upload_id
            source_ip = detections[0].source_ip
        else:
            upload_id = "unknown"
            source_ip = "unknown"

        return RiskAssessment(
            upload_id=upload_id,
            source_ip=source_ip,
            score=total_score,
            severity=severity,
            detection_types=unique_types,
        )

    def _severity_for_score(self, score: int) -> DetectionSeverity:
        if score >= 75:
            return DetectionSeverity.CRITICAL
        if score >= 50:
            return DetectionSeverity.HIGH
        if score >= 25:
            return DetectionSeverity.MEDIUM
        return DetectionSeverity.LOW
