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
from app.models.security_catalog import get_rule_metadata
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
            analysis=analysis,
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
                f"SentinelAI detected a {risk['severity']} severity incident involving {detection_types}. "
                f"Correlated detections indicate {attack_chain} mapped to {mitre_techniques}."
            ),
            attack_narrative=(
                f"Correlated detections indicate the activity progressed through {attack_chain} and involved {detection_types}."
            ),
            mitre_analysis=(
                f"Mapped MITRE ATT&CK techniques: {mitre_techniques}."
            ),
            business_impact=(
                f"Observed detections support identity and operational impact with risk score {risk['score']}."
            ),
            recommended_actions=[
                "Review authentication logs",
                "Inspect sudo history",
                "Audit cron tasks",
                "Reset impacted credentials",
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
        analysis: dict[str, Any],
    ) -> dict[str, Any]:
        detections = analysis.get("detections", [])
        risk_assessment = analysis.get("risk_assessment", {})
        investigation = analysis.get("investigation", {})
        timeline = analysis.get("timeline", {})

        normalized_detections = ReportGenerationService._normalize_detections(
            detections, investigation
        )
        attack_chain = ReportGenerationService._build_attack_chain(
            normalized_detections, investigation, timeline
        )
        metadata = ReportGenerationService._build_metadata(
            risk_assessment=risk_assessment,
            investigation=investigation,
            detections=normalized_detections,
        )
        iocs = ReportGenerationService._build_iocs(normalized_detections)
        mitre_table = ReportGenerationService._build_mitre_table(
            normalized_detections, investigation
        )
        recommendations = ReportGenerationService._build_recommendations(
            normalized_detections
        )
        executive_narrative = ReportGenerationService._build_executive_narrative(
            attack_chain, normalized_detections
        )
        business_impact = ReportGenerationService._build_business_impact(
            normalized_detections
        )
        business_impact_details = ReportGenerationService._build_business_impact_details(
            normalized_detections
        )

        return {
            "upload_id": upload_id,
            "source_ip": source_ip,
            "severity": severity,
            "risk_score": risk_score,
            "executive_summary": content.executive_summary,
            "executive_narrative": executive_narrative,
            "attack_narrative": ReportGenerationService._build_attack_narrative(
                attack_chain, content
            ),
            "business_impact": business_impact,
            "business_impact_details": business_impact_details,
            "mitre_analysis": content.mitre_analysis,
            "recommended_actions": content.recommended_actions,
            "attack_chain": attack_chain,
            "metadata": metadata,
            "iocs": iocs,
            "mitre_table": mitre_table,
            "recommendations": recommendations,
            "generated_at": datetime.now(UTC),
        }

    @staticmethod
    def _normalize_detections(
        detections: list[dict[str, Any]], investigation: dict[str, Any]
    ) -> list[dict[str, Any]]:
        normalized = []
        for detection in detections:
            detection_type = str(detection.get("detection_type") or "")
            details = detection.get("details") or {}
            if isinstance(details, dict):
                details = dict(details)
            else:
                details = {}
            mitre_techniques = list(detection.get("mitre_techniques") or [])
            if not mitre_techniques:
                catalog_entry = get_rule_metadata(detection_type)
                if catalog_entry:
                    mitre_techniques = list(catalog_entry.mitre_techniques)
            if not mitre_techniques:
                detection_type_mappings = {
                    "brute_force": ["T1110"],
                    "password_spray": ["T1110"],
                    "credential_access": ["T1110"],
                    "authentication_abuse": ["T1110"],
                    "sudo": ["T1548"],
                    "setuid": ["T1548"],
                    "scheduled_task": ["T1053"],
                    "cron": ["T1053"],
                    "startup_persistence": ["T1547"],
                    "command_execution": ["T1059"],
                    "powershell": ["T1059"],
                    "bash_execution": ["T1059"],
                }
                mitre_techniques = detection_type_mappings.get(
                    detection_type, []
                )
            if not mitre_techniques and investigation.get("mitre_techniques"):
                mitre_techniques = list(investigation.get("mitre_techniques") or [])
            normalized.append(
                {
                    **detection,
                    "detection_type": detection_type,
                    "details": details,
                    "mitre_techniques": mitre_techniques,
                }
            )
        if not normalized and investigation.get("attack_chain"):
            for phase in investigation.get("attack_chain") or []:
                normalized.append(
                    {
                        "detection_type": str(phase),
                        "source_ip": "",
                        "confidence": 0.0,
                        "details": {},
                        "mitre_techniques": [],
                    }
                )
        return normalized

    @staticmethod
    def _build_attack_chain(
        detections: list[dict[str, Any]],
        investigation: dict[str, Any],
        timeline: dict[str, Any],
    ) -> list[dict[str, Any]]:
        phase_map = [
            ("Initial Access", ["brute_force", "password_spray", "credential_access", "authentication_abuse"]),
            ("Privilege Escalation", ["sudo", "setuid"]),
            ("Persistence", ["account_creation", "credential_modification", "scheduled_task", "cron", "startup_persistence"]),
            ("Defense Evasion", ["firewall_evasion", "disable_security_tools", "tamper_protection"]),
            ("Execution", ["command_execution", "powershell", "bash_execution"]),
            ("Discovery", ["system_information", "recon"]),
            ("Lateral Movement", ["lateral_movement"]),
            ("Collection", ["collection"]),
            ("Exfiltration", ["data_exfiltration"]),
            ("Command & Control", ["command_and_control"]),
        ]

        grouped: list[dict[str, Any]] = []
        for phase_name, detection_types in phase_map:
            matches = [
                d for d in detections if str(d.get("detection_type") or "") in detection_types
            ]
            if not matches:
                continue
            evidence = {
                "ips": sorted({d.get("source_ip") for d in matches if d.get("source_ip")}),
                "users": sorted(
                    {
                        str(d.get("details", {}).get("user", ""))
                        for d in matches
                        if d.get("details", {}).get("user")
                    }
                ),
                "hosts": sorted(
                    {
                        str(d.get("details", {}).get("host", ""))
                        for d in matches
                        if d.get("details", {}).get("host")
                    }
                ),
                "processes": sorted(
                    {
                        str(d.get("details", {}).get("process", ""))
                        for d in matches
                        if d.get("details", {}).get("process")
                    }
                ),
            }
            grouped.append(
                {
                    "name": phase_name,
                    "detections": sorted({str(m.get("detection_type") or "") for m in matches}),
                    "mitre": sorted(
                        {
                            technique
                            for m in matches
                            for technique in m.get("mitre_techniques", [])
                        }
                    ),
                    "evidence": {k: v for k, v in evidence.items() if v},
                }
            )

        if not grouped:
            chain = timeline.get("attack_chain") or investigation.get("attack_chain") or []
            grouped = [
                {
                    "name": str(phase).replace("_", " ").title(),
                    "detections": [],
                    "mitre": [],
                    "evidence": {},
                }
                for phase in chain
            ]

        return grouped

    @staticmethod
    def _collect_key_evidence(detection: dict[str, Any]) -> list[str]:
        evidence: list[str] = []
        if detection.get("source_ip"):
            evidence.append(f"IP: {detection['source_ip']}")
        details = detection.get("details") or {}
        if isinstance(details, dict):
            for key in ("user", "host", "process", "command", "description"):
                value = details.get(key)
                if value:
                    evidence.append(f"{key.title()}: {value}")
        return evidence

    @staticmethod
    def _build_metadata(
        *,
        risk_assessment: dict[str, Any],
        investigation: dict[str, Any],
        detections: list[dict[str, Any]],
    ) -> dict[str, Any]:
        confidence_values = [float(d.get("confidence", 0.0)) for d in detections if d.get("confidence") is not None]
        confidence = round(sum(confidence_values) / max(1, len(confidence_values)), 2) if confidence_values else 0.0
        accounts = sorted(
            {
                str(d.get("details", {}).get("user", ""))
                for d in detections
                if d.get("details", {}).get("user")
            }
        )
        hosts = sorted({d.get("source_ip", "") for d in detections if d.get("source_ip")})
        return {
            "severity": str(risk_assessment.get("severity") or investigation.get("severity") or "unknown"),
            "risk_score": int(risk_assessment.get("score") or investigation.get("risk_score") or 0),
            "confidence": confidence,
            "detection_count": len(detections),
            "correlated_event_count": len([d for d in detections if str(d.get("detection_type") or "")]),
            "affected_hosts": hosts,
            "affected_accounts": accounts,
            "time_window": "Observed during normalized analysis",
            "mitre_techniques_observed": sorted({tech for d in detections for tech in d.get("mitre_techniques", [])}),
        }

    @staticmethod
    def _build_iocs(detections: list[dict[str, Any]]) -> dict[str, Any]:
        details = [d.get("details") or {} for d in detections if isinstance(d.get("details"), dict)]
        external_ips = []
        internal_ips = []
        hosts = []
        accounts = sorted(
            {
                str(d.get("details", {}).get("user", ""))
                for d in detections
                if d.get("details", {}).get("user")
            }
        )
        processes = sorted(
            {
                str(d.get("details", {}).get("process", ""))
                for d in detections
                if d.get("details", {}).get("process")
            }
        )
        commands = sorted(
            {
                str(d.get("details", {}).get("command", ""))
                for d in detections
                if d.get("details", {}).get("command")
            }
        )
        files = sorted(
            {
                str(d.get("details", {}).get("file", ""))
                for d in detections
                if d.get("details", {}).get("file")
            }
        )
        registry_keys = sorted(
            {
                str(d.get("details", {}).get("registry_key", ""))
                for d in detections
                if d.get("details", {}).get("registry_key")
            }
        )
        cron_jobs = sorted(
            {
                str(d.get("details", {}).get("cron", ""))
                for d in detections
                if d.get("details", {}).get("cron")
            }
        )
        domains = sorted(
            {
                str(d.get("details", {}).get("domain", ""))
                for d in detections
                if d.get("details", {}).get("domain")
            }
        )
        urls = sorted(
            {
                str(d.get("details", {}).get("url", ""))
                for d in detections
                if d.get("details", {}).get("url")
            }
        )
        hashes = sorted(
            {
                str(d.get("details", {}).get("hash", ""))
                for d in detections
                if d.get("details", {}).get("hash")
            }
        )
        ips = sorted({d.get("source_ip") for d in detections if d.get("source_ip")})
        return {
            "ips": ips,
            "external_ips": external_ips,
            "internal_ips": internal_ips,
            "hosts": hosts,
            "accounts": accounts,
            "processes": processes,
            "commands": commands,
            "files": files,
            "registry_keys": registry_keys,
            "cron_jobs": cron_jobs,
            "domains": domains,
            "urls": urls,
            "hashes": hashes,
        }

    @staticmethod
    def _build_mitre_table(
        detections: list[dict[str, Any]],
        investigation: dict[str, Any],
    ) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for detection in detections:
            for technique in detection.get("mitre_techniques", []) or []:
                key = (technique, str(detection.get("detection_type") or "unknown"))
                if key in seen:
                    continue
                seen.add(key)
                rows.append(
                    {
                        "technique": str(detection.get("detection_type") or "unknown"),
                        "mitre_id": technique,
                        "evidence": ", ".join(ReportGenerationService._collect_key_evidence(detection)) or "Observed detection context",
                        "source_detection": str(detection.get("detection_type") or "unknown"),
                    }
                )
        if not rows:
            for technique in investigation.get("mitre_techniques", []) or []:
                rows.append(
                    {
                        "technique": "Observed technique",
                        "mitre_id": technique,
                        "evidence": "Normalized detection context",
                        "source_detection": "normalized_detection",
                    }
                )
        return rows

    @staticmethod
    def _build_recommendations(detections: list[dict[str, Any]]) -> dict[str, Any]:
        detection_types = {str(d.get("detection_type") or "") for d in detections}
        return {
            "immediate_containment": [
                "Block observed IPs",
                "Isolate affected hosts",
                "Disable impacted accounts",
                "Remove persistence mechanisms",
            ] if detection_types else [],
            "investigation": [
                "Review authentication logs",
                "Inspect sudo history and privilege changes",
                "Audit scheduled tasks and cron entries",
                "Review account creation and credential changes",
            ],
            "recovery": [
                "Reset compromised credentials",
                "Remove malicious artifacts",
                "Restore affected system integrity",
            ],
            "hardening": [
                "Enforce MFA",
                "Apply least privilege",
                "Patch exposed vectors",
                "Improve EDR coverage",
            ],
        }

    @staticmethod
    def _build_executive_narrative(
        attack_chain: list[dict[str, Any]], detections: list[dict[str, Any]]
    ) -> str:
        if not attack_chain:
            return "No evidence-based attack progression was observed."
        phases = [phase["name"] for phase in attack_chain if phase.get("name")]
        if len(phases) >= 3:
            return (
                f"Observed activity progressed from {phases[0]} to {phases[-1]} with correlated evidence in {', '.join(phases[1:-1] or [])}."
            )
        return f"Observed activity was correlated across the identified phases: {', '.join(phases)}."

    @staticmethod
    def _build_attack_narrative(
        attack_chain: list[dict[str, Any]], content: GeminiReportContent
    ) -> str:
        if attack_chain:
            phases = [phase["name"] for phase in attack_chain if phase.get("name")]
            detections = [
                detection
                for phase in attack_chain
                for detection in phase.get("detections", []) or []
            ]
            if phases:
                if detections:
                    return (
                        f"The incident evidence progressed through {', '.join(phases)} "
                        f"and included detections for {', '.join(detections)}."
                    )
                return f"The incident evidence progressed through {', '.join(phases)}."
        return content.attack_narrative

    @staticmethod
    def _build_business_impact(detections: list[dict[str, Any]]) -> str:
        details = ReportGenerationService._build_business_impact_details(detections)
        parts = []
        if details["confidentiality"]:
            parts.append("Confidentiality impact: " + "; ".join(details["confidentiality"]))
        if details["integrity"]:
            parts.append("Integrity impact: " + "; ".join(details["integrity"]))
        if details["availability"]:
            parts.append("Availability impact: " + "; ".join(details["availability"]))
        if details["identity"]:
            parts.append("Identity impact: " + "; ".join(details["identity"]))
        if details["operational"]:
            parts.append("Operational impact: " + "; ".join(details["operational"]))
        if details["compliance"]:
            parts.append("Compliance impact: " + "; ".join(details["compliance"]))
        return " ".join(parts) if parts else "No evidence-based business impact was observed."

    @staticmethod
    def _build_business_impact_details(detections: list[dict[str, Any]]) -> dict[str, list[str]]:
        by_type = {
            "confidentiality": [],
            "integrity": [],
            "availability": [],
            "identity": [],
            "operational": [],
            "compliance": [],
        }
        if any(d.get("detection_type") in {"credential_modification", "account_creation"} for d in detections):
            by_type["identity"].append("Account and credential changes were observed")
        if any(d.get("detection_type") in {"command_execution", "collection", "data_exfiltration"} for d in detections):
            by_type["confidentiality"].append("Data access or collection was observed")
        if any(d.get("detection_type") in {"firewall_evasion", "tamper_protection"} for d in detections):
            by_type["operational"].append("Evasion or tampering activity was observed")
        if any(d.get("detection_type") in {"command_and_control", "data_exfiltration"} for d in detections):
            by_type["availability"].append("External communications were observed")
        return by_type
