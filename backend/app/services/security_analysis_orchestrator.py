from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.core.exceptions import (
    InvalidUploadStateError,
    UploadNotFoundError,
)
from app.core.logging import get_logger
from app.models.upload import UploadStatus
from app.repositories.detection_repository import DetectionRepository
from app.repositories.feature_repository import FeatureRepository
from app.repositories.investigation_repository import InvestigationRepository
from app.repositories.risk_assessment_repository import RiskAssessmentRepository
from app.repositories.upload_repository import UploadRepository
from app.schemas.detections import DetectionSchema
from app.schemas.investigation import InvestigationSchema
from app.schemas.risk import RiskAssessmentSchema
from app.schemas.security_analysis import TimelineSchema
from app.services.detection_engine import DetectionEngine
from app.services.investigation_service import InvestigationService
from app.services.mitre_mapper import MitreMapper
from app.services.risk_scoring_engine import RiskScoringEngine
from app.services.timeline_builder import TimelineBuilder
from app.services.anomaly_detection_service import AnomalyDetectionService


class SecurityAnalysisOrchestrator:

    def __init__(
        self,
        upload_repository: UploadRepository,
        feature_repository: FeatureRepository,
        detection_repository: DetectionRepository,
        risk_repository: RiskAssessmentRepository,
        investigation_repository: InvestigationRepository,
        detection_engine: DetectionEngine,
        mitre_mapper: MitreMapper,
        risk_engine: RiskScoringEngine,
        timeline_builder: TimelineBuilder,
        investigation_service: InvestigationService,
        anomaly_detection_service: AnomalyDetectionService | None = None,

    ) -> None:
        self._upload_repository = upload_repository
        self._feature_repository = feature_repository
        self._detection_repository = detection_repository
        self._risk_repository = risk_repository
        self._investigation_repository = investigation_repository
        self._detection_engine = detection_engine
        self._mitre_mapper = mitre_mapper
        self._risk_engine = risk_engine
        self._timeline_builder = timeline_builder
        self._investigation_service = investigation_service
        self._anomaly_detection_service = anomaly_detection_service


        self._logger = get_logger(__name__)


    async def analyze_upload(self, upload_id: str) -> dict[str, Any]:
        upload = await self._upload_repository.find_by_upload_id(upload_id)
        if upload is None:
            raise UploadNotFoundError(upload_id)

        if upload["status"] == UploadStatus.ANALYZING.value:
            raise InvalidUploadStateError(f"Upload {upload_id} is already being analyzed")
        if upload["status"] == UploadStatus.ANALYZED.value:
            existing = await self.get_analysis(upload_id)
            return {
                "upload_id": upload_id,
                "risk_score": existing["risk_assessment"]["score"],
                "severity": existing["risk_assessment"]["severity"],
                "detection_count": len(existing["detections"]),
                "investigation_id": existing["investigation"]["investigation_id"],
            }

        if upload["status"] != UploadStatus.FEATURES_GENERATED.value:
            raise InvalidUploadStateError("Upload must have generated features before analysis")

        claimed = await self._upload_repository.transition_status(
            upload_id,
            expected={UploadStatus.FEATURES_GENERATED},
            target=UploadStatus.ANALYZING,
        )
        if claimed is None:
            raise InvalidUploadStateError(f"Upload {upload_id} is already being analyzed")

        try:
            # Anomaly detection is optional, but we always return a consistent object
            # so the frontend can render it reliably.
            default_anomaly_detection = {
                "anomaly_score": 0,
                "is_anomalous": False,
            }

            features = await self._feature_repository.find_by_upload_id(upload_id)

            self._logger.info(
                "analysis_started", extra={"upload_id": upload_id, "feature_count": len(features)}
            )

            detections = self._detection_engine.detect(features)
            detection_docs = [
                {
                    **d.model_dump(),
                    "mitre_techniques": self._mitre_mapper.map_detection(d),
                }
                for d in detections
            ]
            await self._detection_repository.insert_detections(detection_docs)
            self._logger.info(
                "detections_generated",
                extra={"upload_id": upload_id, "detection_count": len(detection_docs)},
            )

            mitre_techniques = self._mitre_mapper.map_detections(detections)
            risk_assessment = self._risk_engine.score_detections(detections)
            if not detections:
                risk_assessment.upload_id = upload_id
                risk_assessment.source_ip = "unknown"
            await self._risk_repository.insert_risk_assessments([risk_assessment.model_dump()])
            self._logger.info(
                "risk_assessed",
                extra={"upload_id": upload_id, "risk_score": risk_assessment.score},
            )

            timeline = self._timeline_builder.build_attack_chain(detections)
            self._logger.info(
                "timeline_built", extra={"upload_id": upload_id, "attack_chain": timeline}
            )

            investigation = await self._investigation_service.create_investigation(
                detections,
                risk_assessment=risk_assessment,
                attack_chain=timeline,
                mitre_techniques=mitre_techniques,
            )
            self._logger.info(
                "investigation_created",
                extra={"upload_id": upload_id, "investigation_id": investigation.investigation_id},
            )

            try:
                anomaly_detection = default_anomaly_detection
                if self._anomaly_detection_service is not None:
                    anomaly_detection = await self._anomaly_detection_service.run_for_upload(upload_id)
            except Exception as exc:

                self._logger.warning(
                    "anomaly_detection_integration_failed",
                    extra={"upload_id": upload_id, "error": str(exc)},
                )

            await self._upload_repository.update_analysis_result(
                upload_id,
                status=UploadStatus.ANALYZED,
                analyzed_at=datetime.now(UTC),
            )
            self._logger.info("analysis_completed", extra={"upload_id": upload_id})

            response: dict[str, Any] = {
                "upload_id": upload_id,
                "risk_score": risk_assessment.score,
                "severity": risk_assessment.severity.value,
                "detection_count": len(detection_docs),
                "investigation_id": investigation.investigation_id,
            }
            if anomaly_detection is not None:
                response["anomaly_detection"] = {
                    "anomaly_score": int(anomaly_detection.get("anomaly_score", 0)),
                    "is_anomalous": bool(anomaly_detection.get("is_anomalous", False)),
                }

            return response

        except Exception as exc:
            await self._upload_repository.transition_status(
                upload_id,
                expected={UploadStatus.ANALYZING},
                target=UploadStatus.FAILED,
            )
            self._logger.exception(
                "analysis_failed", extra={"upload_id": upload_id, "error": str(exc)}
            )
            raise

    async def get_analysis(self, upload_id: str) -> dict[str, Any]:
        self._logger.info(
            "get_analysis_entered", extra={"upload_id": upload_id}
        )
        upload = await self._upload_repository.find_by_upload_id(upload_id)

        if upload is None:
            raise UploadNotFoundError(upload_id)

        detection_docs = await self._detection_repository.find_by_upload_id(upload_id)
        risk_docs = await self._risk_repository.find_by_upload_id(upload_id)
        investigation_docs = await self._investigation_repository.find_by_upload_id(upload_id)

        risk_doc = (
            risk_docs[0]
            if risk_docs
            else {
                "risk_id": "unknown",
                "upload_id": upload_id,
                "source_ip": "unknown",
                "score": 0,
                "severity": "low",
                "detection_types": [],
                "generated_at": datetime.now(UTC),
            }
        )
        investigation_doc = (
            investigation_docs[0]
            if investigation_docs
            else {
                "investigation_id": "unknown",
                "upload_id": upload_id,
                "source_ip": "unknown",
                "incident_type": "No Findings",
                "severity": "low",
                "risk_score": risk_doc["score"],
                "attack_chain": [],
                "detections": [],
                "mitre_techniques": [],
                "generated_at": datetime.now(UTC),
            }
        )

        validated_detections = [DetectionSchema.model_validate(doc) for doc in detection_docs]
        validated_risk = RiskAssessmentSchema.model_validate(risk_doc)
        validated_investigation = InvestigationSchema.model_validate(investigation_doc)
        validated_timeline = TimelineSchema(attack_chain=validated_investigation.attack_chain)

        # Keep anomaly_detection consistent in the analysis response.
        # (This endpoint is used by the frontend.)
        default_anomaly_detection = {
            "anomaly_score": 0,
            "is_anomalous": False,
        }
        anomaly_detection = default_anomaly_detection
        # NOTE: Import/DI wiring can fail; never block analysis.
        try:
            if self._anomaly_detection_service is not None:
                anomaly_detection = await self._anomaly_detection_service.run_for_upload(upload_id)
        except Exception as exc:
            self._logger.warning(
                "anomaly_detection_integration_failed",
                extra={"upload_id": upload_id, "error": str(exc)},
            )

        # Always return anomaly_detection with correct score keys
        response: dict[str, Any] = {
            "upload_id": upload_id,
            "detections": [d.model_dump(mode="json") for d in validated_detections],
            "risk_assessment": validated_risk.model_dump(mode="json"),
            "timeline": validated_timeline.model_dump(mode="json"),
            "investigation": validated_investigation.model_dump(mode="json"),
            "anomaly_detection": {
                "anomaly_score": int(anomaly_detection.get("anomaly_score", 0)),
                "is_anomalous": bool(anomaly_detection.get("is_anomalous", False)),
            },
        }

        self._logger.info(
            "get_analysis_returning",
            extra={
                "upload_id": upload_id,
                "response_keys": list(response.keys()),
                "has_anomaly_detection": "anomaly_detection" in response,
                "anomaly_detection": response.get("anomaly_detection"),
            },
        )
        return response


