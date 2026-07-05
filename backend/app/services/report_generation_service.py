"""Orchestrates AI security report generation and persistence."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.core.exceptions import (
    InvalidUploadStateError,
    ReportNotFoundError,
    UploadNotFoundError,
)
from app.core.logging import get_logger
from app.models.upload import UploadStatus
from app.repositories.report_repository import ReportRepository
from app.repositories.upload_repository import UploadRepository
from app.schemas.report import (
    GeminiReportContent,
    ReportGenerateResponse,
    SecurityReportSchema,
)
from app.services.gemini_service import GeminiService, GeminiServiceError
from app.services.security_analysis_orchestrator import SecurityAnalysisOrchestrator


class ReportGenerationService:
    def __init__(
        self,
        upload_repository: UploadRepository,
        report_repository: ReportRepository,
        analysis_orchestrator: SecurityAnalysisOrchestrator,
        gemini_service: GeminiService,
    ) -> None:
        self._upload_repository = upload_repository
        self._report_repository = report_repository
        self._analysis_orchestrator = analysis_orchestrator
        self._gemini_service = gemini_service
        self._logger = get_logger(__name__)

    async def generate_report(self, upload_id: str) -> ReportGenerateResponse:
        upload = await self._upload_repository.find_by_upload_id(upload_id)
        if upload is None:
            raise UploadNotFoundError(upload_id)

        if upload["status"] != UploadStatus.ANALYZED.value:
            raise InvalidUploadStateError(
                f"Upload {upload_id} must be analyzed before generating a report"
            )

        analysis = await self._analysis_orchestrator.get_analysis(upload_id)
        risk_assessment = analysis["risk_assessment"]
        investigation = analysis["investigation"]

        self._logger.info("report_generation_started", extra={"upload_id": upload_id})

        ai_content = await self._generate_ai_content(analysis)
        report_doc = self._build_report_document(
            upload_id=upload_id,
            source_ip=risk_assessment["source_ip"],
            severity=str(risk_assessment["severity"]),
            risk_score=risk_assessment["score"],
            content=ai_content,
        )

        stored = await self._report_repository.upsert_report(report_doc)
        validated = SecurityReportSchema.model_validate(stored)

        self._logger.info(
            "report_generation_completed",
            extra={"upload_id": upload_id, "report_id": validated.report_id},
        )

        return ReportGenerateResponse(
            report_id=validated.report_id,
            upload_id=validated.upload_id,
            severity=validated.severity,
            risk_score=validated.risk_score,
        )

    async def get_report(self, upload_id: str) -> SecurityReportSchema:
        upload = await self._upload_repository.find_by_upload_id(upload_id)
        if upload is None:
            raise UploadNotFoundError(upload_id)

        report = await self._report_repository.find_by_upload_id(upload_id)
        if report is None:
            raise ReportNotFoundError(upload_id)

        return SecurityReportSchema.model_validate(report)

    async def _generate_ai_content(self, analysis: dict[str, Any]) -> GeminiReportContent:
        try:
            return await self._gemini_service.generate_security_report(
                detections=analysis["detections"],
                risk_assessment=analysis["risk_assessment"],
                timeline=analysis["timeline"],
                investigation=analysis["investigation"],
            )
        except (GeminiServiceError, Exception) as exc:
            self._logger.warning(
                "gemini_generation_failed_using_fallback",
                extra={"upload_id": analysis["upload_id"], "error": str(exc)},
            )
            return self._build_fallback_content(analysis)

    @staticmethod
    def _build_fallback_content(analysis: dict[str, Any]) -> GeminiReportContent:
        investigation = analysis["investigation"]
        risk = analysis["risk_assessment"]
        timeline = analysis["timeline"]
        detections = analysis["detections"]

        detection_types = ", ".join(
            sorted({d["detection_type"] for d in detections})
        ) or "none"
        attack_chain = " → ".join(timeline.get("attack_chain") or []) or "unknown"
        mitre_techniques = ", ".join(investigation.get("mitre_techniques") or []) or "none"

        return GeminiReportContent(
            executive_summary=(
                f"SentinelAI detected a {risk['severity']} severity incident "
                f"(risk score {risk['score']}) involving source IP {risk['source_ip']}. "
                f"Incident type: {investigation.get('incident_type', 'Unknown')}."
            ),
            attack_narrative=(
                f"Analysis identified {len(detections)} detection(s) "
                f"({detection_types}). Attack chain phases: {attack_chain}."
            ),
            mitre_analysis=(
                f"Mapped MITRE ATT&CK techniques: {mitre_techniques}."
            ),
            business_impact=(
                f"Risk score {risk['score']} with {risk['severity']} severity "
                "signals elevated likelihood of hostile activity consistent with the incident type, with risk score and severity used to prioritize response."
            ),
            recommended_actions=[
                "Review authentication logs for affected source IP",
                "Validate detection findings against host and network telemetry",
                "Contain or isolate affected systems if compromise is confirmed",
                "Rotate credentials for potentially exposed accounts",
                "Document findings and escalate per incident response procedures",
            ],
        )

    @staticmethod
    def _build_report_document(
        *,
        upload_id: str,
        source_ip: str,
        severity: str,
        risk_score: int,
        content: GeminiReportContent,
    ) -> dict[str, Any]:
        return {
            "upload_id": upload_id,
            "source_ip": source_ip,
            "severity": severity,
            "risk_score": risk_score,
            "executive_summary": content.executive_summary,
            "attack_narrative": content.attack_narrative,
            "business_impact": content.business_impact,
            "mitre_analysis": content.mitre_analysis,
            "recommended_actions": content.recommended_actions,
            "generated_at": datetime.now(UTC),
        }
