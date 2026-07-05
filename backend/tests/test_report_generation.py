"""Unit tests for AI security report generation."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.exceptions import (
    InvalidUploadStateError,
    ReportNotFoundError,
    UploadNotFoundError,
)
from app.dependencies import get_report_generation_service
from app.models.upload import UploadStatus
from app.prompts.security_report_prompt import SYSTEM_PROMPT, build_user_prompt
from app.schemas.report import GeminiReportContent
from app.services.gemini_service import GeminiService, GeminiServiceError
from app.services.report_generation_service import ReportGenerationService
from tests.support.in_memory_upload_repository import InMemoryUploadRepository


SAMPLE_ANALYSIS: dict[str, Any] = {
    "upload_id": "upload-123",
    "detections": [
        {
            "detection_id": "det-1",
            "upload_id": "upload-123",
            "source_ip": "203.0.113.10",
            "detection_type": "brute_force",
            "severity": "critical",
            "confidence": 0.95,
            "details": {"failed_attempts": 42},
            "generated_at": "2026-06-12T10:00:00+00:00",
        }
    ],
    "risk_assessment": {
        "risk_id": "risk-1",
        "upload_id": "upload-123",
        "source_ip": "203.0.113.10",
        "score": 92,
        "severity": "critical",
        "detection_types": ["brute_force"],
        "generated_at": "2026-06-12T10:00:00+00:00",
    },
    "timeline": {"attack_chain": ["initial_access", "persistence"]},
    "investigation": {
        "investigation_id": "inv-1",
        "upload_id": "upload-123",
        "source_ip": "203.0.113.10",
        "incident_type": "Credential Compromise",
        "severity": "critical",
        "risk_score": 92,
        "attack_chain": ["initial_access", "persistence"],
        "detections": [{"detection_type": "brute_force"}],
        "mitre_techniques": ["T1110", "T1053"],
        "generated_at": "2026-06-12T10:00:00+00:00",
    },
}

MOCK_GEMINI_CONTENT = GeminiReportContent(
    executive_summary=(
        "SentinelAI detected a critical security incident involving a successful "
        "brute-force attack against a privileged account."
    ),
    attack_narrative=(
        "The attacker performed multiple failed authentication attempts before "
        "successfully accessing a root account."
    ),
    mitre_analysis="Techniques T1110 and T1053 were observed during the incident.",
    business_impact="Potential full host compromise and unauthorized privileged access.",
    recommended_actions=[
        "Disable affected accounts",
        "Rotate credentials",
        "Audit cron jobs",
    ],
)


class InMemoryReportRepository:
    def __init__(self) -> None:
        self.reports: dict[str, dict[str, Any]] = {}

    async def upsert_report(self, report: dict[str, Any]) -> dict[str, Any]:
        report.setdefault("report_id", "report-abc")
        report.setdefault("generated_at", datetime.now(UTC))
        self.reports[report["upload_id"]] = report
        return report

    async def find_by_upload_id(self, upload_id: str) -> dict[str, Any] | None:
        return self.reports.get(upload_id)


class MockAnalysisOrchestrator:
    def __init__(self, analysis: dict[str, Any] | None = None) -> None:
        self.analysis = analysis or SAMPLE_ANALYSIS

    async def get_analysis(self, upload_id: str) -> dict[str, Any]:
        return {**self.analysis, "upload_id": upload_id}


class MockGeminiService:
    def __init__(
        self,
        content: GeminiReportContent | None = None,
        error: Exception | None = None,
    ) -> None:
        self.content = content or MOCK_GEMINI_CONTENT
        self.error = error
        self.calls: list[dict[str, Any]] = []

    async def generate_security_report(self, **kwargs: Any) -> GeminiReportContent:
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return self.content


async def build_report_service(
    *,
    upload_repo: InMemoryUploadRepository | None = None,
    report_repo: InMemoryReportRepository | None = None,
    orchestrator: MockAnalysisOrchestrator | None = None,
    gemini: MockGeminiService | None = None,
    upload_status: UploadStatus = UploadStatus.ANALYZED,
) -> tuple[ReportGenerationService, str, InMemoryReportRepository]:
    upload_repo = upload_repo or InMemoryUploadRepository()
    report_repo = report_repo or InMemoryReportRepository()
    orchestrator = orchestrator or MockAnalysisOrchestrator()
    gemini = gemini or MockGeminiService()

    upload_doc = await upload_repo.create_pending(
        original_name="auth.log",
        stored_filename="auth.log",
        size_bytes=100,
    )
    upload_id = upload_doc["upload_id"]
    if upload_status != UploadStatus.PENDING:
        await upload_repo.update_status(upload_id, upload_status)

    service = ReportGenerationService(
        upload_repository=upload_repo,
        report_repository=report_repo,
        analysis_orchestrator=orchestrator,  # type: ignore[arg-type]
        gemini_service=gemini,  # type: ignore[arg-type]
    )
    return service, upload_id, report_repo


@pytest.mark.asyncio
async def test_generate_report_success_with_mocked_gemini():
    service, upload_id, report_repo = await build_report_service()

    result = await service.generate_report(upload_id)

    assert result.upload_id == upload_id
    assert result.severity == "critical"
    assert result.risk_score == 92
    assert result.report_id == "report-abc"

    stored = report_repo.reports[upload_id]
    assert stored["executive_summary"] == MOCK_GEMINI_CONTENT.executive_summary
    assert stored["recommended_actions"] == MOCK_GEMINI_CONTENT.recommended_actions


@pytest.mark.asyncio
async def test_generate_report_passes_analysis_context_to_gemini():
    gemini = MockGeminiService()
    service, upload_id, _ = await build_report_service(gemini=gemini)

    await service.generate_report(upload_id)

    assert len(gemini.calls) == 1
    call = gemini.calls[0]
    assert call["detections"][0]["detection_type"] == "brute_force"
    assert call["risk_assessment"]["score"] == 92
    assert call["timeline"]["attack_chain"] == ["initial_access", "persistence"]


@pytest.mark.asyncio
async def test_generate_report_stores_fallback_when_gemini_fails():
    gemini = MockGeminiService(error=GeminiServiceError("API unavailable"))
    service, upload_id, report_repo = await build_report_service(gemini=gemini)

    result = await service.generate_report(upload_id)

    assert result.risk_score == 92
    stored = report_repo.reports[upload_id]
    assert "SentinelAI detected a critical severity incident" in stored["executive_summary"]
    assert stored["recommended_actions"]
    assert "Review authentication logs" in stored["recommended_actions"][0]


@pytest.mark.asyncio
async def test_generate_report_stores_fallback_on_unexpected_gemini_error():
    gemini = MockGeminiService(error=RuntimeError("network timeout"))
    service, upload_id, report_repo = await build_report_service(gemini=gemini)

    result = await service.generate_report(upload_id)

    assert result.report_id == "report-abc"
    assert "brute_force" in report_repo.reports[upload_id]["attack_narrative"]


@pytest.mark.asyncio
async def test_generate_report_builds_structured_attack_chain_and_iocs():
    service, upload_id, report_repo = await build_report_service()

    await service.generate_report(upload_id)

    stored = report_repo.reports[upload_id]
    phase = stored["attack_chain"][0]
    assert phase["name"] == "Initial Access"
    assert phase["detections"] == ["brute_force"]
    assert phase["mitre"] == ["T1110"]
    assert phase["evidence"]["ips"] == ["203.0.113.10"]
    assert stored["metadata"]["detection_count"] == 1
    assert stored["metadata"]["correlated_event_count"] == 1
    assert stored["iocs"]["ips"] == ["203.0.113.10"]
    assert stored["recommendations"]["immediate_containment"]


@pytest.mark.asyncio
async def test_generate_report_upload_not_found():
    service, _, _ = await build_report_service()

    with pytest.raises(UploadNotFoundError):
        await service.generate_report("missing-upload")


@pytest.mark.asyncio
async def test_generate_report_requires_analyzed_upload():
    service, upload_id, _ = await build_report_service(
        upload_status=UploadStatus.FEATURES_GENERATED,
    )

    with pytest.raises(InvalidUploadStateError):
        await service.generate_report(upload_id)


@pytest.mark.asyncio
async def test_get_report_returns_stored_report():
    service, upload_id, _ = await build_report_service()
    await service.generate_report(upload_id)

    report = await service.get_report(upload_id)

    assert report.upload_id == upload_id
    assert report.source_ip == "203.0.113.10"
    assert report.mitre_analysis == MOCK_GEMINI_CONTENT.mitre_analysis


@pytest.mark.asyncio
async def test_get_report_not_found():
    service, upload_id, _ = await build_report_service()

    with pytest.raises(ReportNotFoundError):
        await service.get_report(upload_id)


@pytest.mark.asyncio
async def test_get_report_upload_not_found():
    service, _, _ = await build_report_service()

    with pytest.raises(UploadNotFoundError):
        await service.get_report("missing-upload")


def test_build_user_prompt_includes_all_analysis_sections():
    prompt = build_user_prompt(
        detections=SAMPLE_ANALYSIS["detections"],
        risk_assessment=SAMPLE_ANALYSIS["risk_assessment"],
        timeline=SAMPLE_ANALYSIS["timeline"],
        investigation=SAMPLE_ANALYSIS["investigation"],
    )

    assert "brute_force" in prompt
    assert "T1110" in prompt
    assert "initial_access" in prompt
    assert "risk_assessment" in prompt


def test_system_prompt_defines_soc_analyst_role():
    assert "Senior SOC Analyst" in SYSTEM_PROMPT
    assert "Executive Summary" in SYSTEM_PROMPT
    assert "Do not invent information" in SYSTEM_PROMPT


@pytest.mark.asyncio
async def test_gemini_service_raises_without_api_key():
    service = GeminiService(api_key="")

    with pytest.raises(GeminiServiceError, match="GEMINI_API_KEY"):
        await service.generate_security_report(
            detections=[],
            risk_assessment={},
            timeline={},
            investigation={},
        )


@pytest.mark.asyncio
async def test_gemini_service_parses_successful_response():
    service = GeminiService(api_key="test-key")
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {
                            "text": MOCK_GEMINI_CONTENT.model_dump_json(),
                        }
                    ]
                }
            }
        ]
    }

    with patch("app.services.gemini_service.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.post.return_value = mock_response
        mock_client_cls.return_value = mock_client

        content = await service.generate_security_report(
            detections=SAMPLE_ANALYSIS["detections"],
            risk_assessment=SAMPLE_ANALYSIS["risk_assessment"],
            timeline=SAMPLE_ANALYSIS["timeline"],
            investigation=SAMPLE_ANALYSIS["investigation"],
        )

    assert content.executive_summary == MOCK_GEMINI_CONTENT.executive_summary
    assert content.recommended_actions == MOCK_GEMINI_CONTENT.recommended_actions


@pytest.mark.asyncio
async def test_gemini_service_raises_on_http_error():
    service = GeminiService(api_key="test-key")
    mock_response = MagicMock()
    mock_response.status_code = 503
    mock_response.text = "Service unavailable"

    with patch("app.services.gemini_service.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.post.return_value = mock_response
        mock_client_cls.return_value = mock_client

        with pytest.raises(GeminiServiceError, match="503"):
            await service.generate_security_report(
                detections=[],
                risk_assessment={},
                timeline={},
                investigation={},
            )


@pytest.mark.asyncio
async def test_report_api_post_and_get_endpoints(app):
    upload_repo = InMemoryUploadRepository()
    report_repo = InMemoryReportRepository()
    orchestrator = MockAnalysisOrchestrator()
    gemini = MockGeminiService()

    upload_doc = await upload_repo.create_pending(
        original_name="auth.log",
        stored_filename="auth.log",
        size_bytes=100,
    )
    await upload_repo.update_status(upload_doc["upload_id"], UploadStatus.ANALYZED)

    service = ReportGenerationService(
        upload_repository=upload_repo,
        report_repository=report_repo,
        analysis_orchestrator=orchestrator,  # type: ignore[arg-type]
        gemini_service=gemini,  # type: ignore[arg-type]
    )
    app.dependency_overrides[get_report_generation_service] = lambda: service

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        post_response = await client.post(
            f"/api/v1/upload/{upload_doc['upload_id']}/report",
        )
        assert post_response.status_code == 200
        post_body = post_response.json()
        assert post_body["upload_id"] == upload_doc["upload_id"]
        assert post_body["severity"] == "critical"
        assert post_body["risk_score"] == 92

        get_response = await client.get(
            f"/api/v1/upload/{upload_doc['upload_id']}/report",
        )
        assert get_response.status_code == 200
        get_body = get_response.json()
        assert get_body["report_id"] == post_body["report_id"]
        assert get_body["executive_summary"] == MOCK_GEMINI_CONTENT.executive_summary

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_report_api_get_returns_404_when_missing(app):
    upload_repo = InMemoryUploadRepository()
    report_repo = InMemoryReportRepository()
    orchestrator = MockAnalysisOrchestrator()
    gemini = MockGeminiService()

    upload_doc = await upload_repo.create_pending(
        original_name="auth.log",
        stored_filename="auth.log",
        size_bytes=100,
    )
    await upload_repo.update_status(upload_doc["upload_id"], UploadStatus.ANALYZED)

    service = ReportGenerationService(
        upload_repository=upload_repo,
        report_repository=report_repo,
        analysis_orchestrator=orchestrator,  # type: ignore[arg-type]
        gemini_service=gemini,  # type: ignore[arg-type]
    )
    app.dependency_overrides[get_report_generation_service] = lambda: service

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get(
            f"/api/v1/upload/{upload_doc['upload_id']}/report",
        )
        assert response.status_code == 404
        assert response.json()["code"] == "REPORT_NOT_FOUND"

    app.dependency_overrides.clear()
