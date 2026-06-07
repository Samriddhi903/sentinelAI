from __future__ import annotations

from datetime import datetime, timezone
from typing import List
from uuid import uuid4

from pydantic import BaseModel, Field

from app.models.security import DetectionSeverity
from app.services.detection_engine import Detection


class RiskAssessment(BaseModel):
    risk_id: str = Field(default_factory=lambda: str(uuid4()))
    upload_id: str
    source_ip: str
    score: int
    severity: DetectionSeverity
    detection_types: List[str]
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RiskScoringEngine:
    WEIGHTS: dict[str, int] = {
        "sql_injection": 25,
        "xss": 15,
        "directory_enumeration": 15,
        "sensitive_file_discovery": 30,
        "path_traversal": 30,
        "brute_force": 20,
        "reconnaissance": 10,
        "privilege_escalation": 50,
        "webshell_activity": 60,
        "critical_file_modification": 50,
        "suspicious_cron": 40,
        "account_creation": 35,
        "credential_modification": 35,
        "command_execution": 25,
        "sensitive_file_access": 30,
        "firewall_evasion": 15,
    }

    def score_detections(self, detections: List[Detection]) -> RiskAssessment:
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
