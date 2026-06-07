from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, List
from uuid import uuid4

from pydantic import BaseModel, Field

from app.models.security import DetectionSeverity
from app.repositories.investigation_repository import InvestigationRepository
from app.services.detection_engine import Detection
from app.services.incident_classifier import IncidentClassifier
from app.services.mitre_mapper import MitreMapper
from app.services.risk_scoring_engine import RiskAssessment, RiskScoringEngine
from app.services.timeline_builder import TimelineBuilder


class Investigation(BaseModel):
    investigation_id: str = Field(default_factory=lambda: str(uuid4()))
    upload_id: str
    source_ip: str
    incident_type: str
    severity: DetectionSeverity
    risk_score: int
    attack_chain: List[str]
    detections: List[dict[str, Any]]
    mitre_techniques: List[str]
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class InvestigationService:
    def __init__(
        self,
        repository: InvestigationRepository,
        risk_engine: RiskScoringEngine,
        timeline_builder: TimelineBuilder,
        mitre_mapper: MitreMapper,
    ) -> None:
        self._repository = repository
        self._risk_engine = risk_engine
        self._timeline_builder = timeline_builder
        self._mitre_mapper = mitre_mapper

    def _infer_incident_type(self, detections: Iterable[Detection]) -> str:
        """Classify incident type using the incident classifier."""
        return IncidentClassifier.classify(detections)

    def _summarize_detections(self, detections: Iterable[Detection]) -> List[dict[str, Any]]:
        return [
            {
                "detection_id": d.detection_id,
                "detection_type": d.detection_type,
                "severity": d.severity.value,
                "confidence": d.confidence,
                "generated_at": d.generated_at,
            }
            for d in detections
        ]

    async def create_investigation(
        self,
        detections: List[Detection],
        risk_assessment: RiskAssessment | None = None,
        attack_chain: list[str] | None = None,
        mitre_techniques: list[str] | None = None,
    ) -> Investigation:
        if risk_assessment is None:
            risk_assessment = self._risk_engine.score_detections(detections)
        if attack_chain is None:
            attack_chain = self._timeline_builder.build_attack_chain(detections)
        if mitre_techniques is None:
            mitre_techniques = self._mitre_mapper.map_detections(detections)

        incident_type = self._infer_incident_type(detections) if detections else "No Findings"
        severity = risk_assessment.severity if detections else DetectionSeverity.LOW
        risk_score = risk_assessment.score if detections else 0
        summary = self._summarize_detections(detections)

        investigation = Investigation(
            upload_id=risk_assessment.upload_id,
            source_ip=risk_assessment.source_ip,
            incident_type=incident_type,
            severity=severity,
            risk_score=risk_score,
            attack_chain=attack_chain,
            detections=summary,
            mitre_techniques=mitre_techniques,
        )

        await self._repository.insert_investigations([investigation.model_dump()])
        return investigation
