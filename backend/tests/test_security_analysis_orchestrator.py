import pytest
from bson import ObjectId

from app.dependencies import get_security_analysis_orchestrator
from app.database.base_repository import BaseRepository
from app.models.upload import UploadStatus
from app.repositories.detection_repository import DetectionRepository
from app.services.detection_engine import DetectionEngine
from app.services.investigation_service import InvestigationService
from app.services.mitre_mapper import MitreMapper
from app.services.risk_scoring_engine import RiskScoringEngine
from app.services.timeline_builder import TimelineBuilder
from app.services.security_analysis_orchestrator import SecurityAnalysisOrchestrator
from tests.support.in_memory_upload_repository import InMemoryUploadRepository
from tests.support.in_memory_feature_repository import InMemoryFeatureRepository


class InMemoryDetectionRepository:
    def __init__(self) -> None:
        self.detections: list[dict[str, object]] = []

    async def insert_detections(self, detections: list[dict[str, object]]) -> None:
        self.detections.extend(detections)

    async def find_by_upload_id(self, upload_id: str) -> list[dict[str, object]]:
        return [d for d in self.detections if d.get("upload_id") == upload_id]


class InMemoryRiskAssessmentRepository:
    def __init__(self) -> None:
        self.assessments: list[dict[str, object]] = []

    async def insert_risk_assessments(self, assessments: list[dict[str, object]]) -> None:
        self.assessments.extend(assessments)

    async def find_by_upload_id(self, upload_id: str) -> list[dict[str, object]]:
        return [r for r in self.assessments if r.get("upload_id") == upload_id]


class InMemoryInvestigationRepository:
    def __init__(self) -> None:
        self.investigations: list[dict[str, object]] = []

    async def insert_investigations(self, investigations: list[dict[str, object]]) -> None:
        self.investigations.extend(investigations)

    async def find_by_upload_id(self, upload_id: str) -> list[dict[str, object]]:
        return [i for i in self.investigations if i.get("upload_id") == upload_id]


@pytest.mark.asyncio
async def test_security_analysis_orchestrator_runs_full_pipeline():
    upload_repo = InMemoryUploadRepository()
    feature_repo = InMemoryFeatureRepository()
    detection_repo = InMemoryDetectionRepository()
    risk_repo = InMemoryRiskAssessmentRepository()
    investigation_repo = InMemoryInvestigationRepository()

    upload_doc = await upload_repo.create_pending(original_name="test.log", stored_filename="test.log", size_bytes=10)
    await upload_repo.update_feature_extraction_result(
        upload_doc["upload_id"],
        status=UploadStatus.FEATURES_GENERATED,
        generated_at=upload_doc["uploaded_at"],
    )

    feature_repo.features.append({
        "upload_id": upload_doc["upload_id"],
        "source_ip": "198.51.100.50",
        "sqli_attempt_count": 1,
        "webshell_access_count": 1,
    })

    orchestrator = SecurityAnalysisOrchestrator(
        upload_repository=upload_repo,
        feature_repository=feature_repo,
        detection_repository=detection_repo,
        risk_repository=risk_repo,
        investigation_repository=investigation_repo,
        detection_engine=DetectionEngine(),
        mitre_mapper=MitreMapper(),
        risk_engine=RiskScoringEngine(),
        timeline_builder=TimelineBuilder(),
        investigation_service=InvestigationService(
            repository=investigation_repo,
            risk_engine=RiskScoringEngine(),
            timeline_builder=TimelineBuilder(),
            mitre_mapper=MitreMapper(),
        ),
    )

    summary = await orchestrator.analyze_upload(upload_doc["upload_id"])

    assert summary["upload_id"] == upload_doc["upload_id"]
    assert summary["risk_score"] == 85
    assert summary["severity"] == "critical"
    assert summary["detection_count"] == 2
    assert summary["investigation_id"] is not None

    assert len(detection_repo.detections) == 2
    assert len(risk_repo.assessments) == 1
    assert len(investigation_repo.investigations) == 1

    analysis = await orchestrator.get_analysis(upload_doc["upload_id"])
    assert analysis["upload_id"] == upload_doc["upload_id"]
    assert analysis["timeline"]["attack_chain"] == ["initial_access", "persistence"]
    assert analysis["investigation"]["incident_type"] == "Web Application Compromise"


@pytest.mark.asyncio
async def test_security_analysis_orchestrator_handles_empty_feature_sets():
    upload_repo = InMemoryUploadRepository()
    feature_repo = InMemoryFeatureRepository()
    detection_repo = InMemoryDetectionRepository()
    risk_repo = InMemoryRiskAssessmentRepository()
    investigation_repo = InMemoryInvestigationRepository()

    upload_doc = await upload_repo.create_pending(original_name="test.log", stored_filename="test.log", size_bytes=10)
    await upload_repo.update_feature_extraction_result(
        upload_doc["upload_id"],
        status=UploadStatus.FEATURES_GENERATED,
        generated_at=upload_doc["uploaded_at"],
    )

    orchestrator = SecurityAnalysisOrchestrator(
        upload_repository=upload_repo,
        feature_repository=feature_repo,
        detection_repository=detection_repo,
        risk_repository=risk_repo,
        investigation_repository=investigation_repo,
        detection_engine=DetectionEngine(),
        mitre_mapper=MitreMapper(),
        risk_engine=RiskScoringEngine(),
        timeline_builder=TimelineBuilder(),
        investigation_service=InvestigationService(
            repository=investigation_repo,
            risk_engine=RiskScoringEngine(),
            timeline_builder=TimelineBuilder(),
            mitre_mapper=MitreMapper(),
        ),
    )

    summary = await orchestrator.analyze_upload(upload_doc["upload_id"])

    assert summary["detection_count"] == 0
    assert summary["risk_score"] == 0
    assert summary["severity"] == "low"
    assert len(risk_repo.assessments) == 1
    assert len(investigation_repo.investigations) == 1


@pytest.mark.asyncio
async def test_analysis_api_endpoints(client, app):
    upload_repo = InMemoryUploadRepository()
    feature_repo = InMemoryFeatureRepository()
    detection_repo = InMemoryDetectionRepository()
    risk_repo = InMemoryRiskAssessmentRepository()
    investigation_repo = InMemoryInvestigationRepository()

    upload_doc = await upload_repo.create_pending(original_name="test.log", stored_filename="test.log", size_bytes=10)
    await upload_repo.update_feature_extraction_result(
        upload_doc["upload_id"],
        status=UploadStatus.FEATURES_GENERATED,
        generated_at=upload_doc["uploaded_at"],
    )

    feature_repo.features.append({
        "upload_id": upload_doc["upload_id"],
        "source_ip": "198.51.100.50",
        "sqli_attempt_count": 1,
        "webshell_access_count": 1,
    })

    orchestrator = SecurityAnalysisOrchestrator(
        upload_repository=upload_repo,
        feature_repository=feature_repo,
        detection_repository=detection_repo,
        risk_repository=risk_repo,
        investigation_repository=investigation_repo,
        detection_engine=DetectionEngine(),
        mitre_mapper=MitreMapper(),
        risk_engine=RiskScoringEngine(),
        timeline_builder=TimelineBuilder(),
        investigation_service=InvestigationService(
            repository=investigation_repo,
            risk_engine=RiskScoringEngine(),
            timeline_builder=TimelineBuilder(),
            mitre_mapper=MitreMapper(),
        ),
    )

    app.dependency_overrides[get_security_analysis_orchestrator] = lambda: orchestrator

    response = await client.post(f"/api/v1/upload/{upload_doc['upload_id']}/analyze")
    assert response.status_code == 200
    assert response.json()["upload_id"] == upload_doc["upload_id"]
    assert response.json()["risk_score"] == 85

    analysis_response = await client.get(f"/api/v1/upload/{upload_doc['upload_id']}/analysis")
    assert analysis_response.status_code == 200
    assert analysis_response.json()["investigation"]["investigation_id"] == response.json()["investigation_id"]

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_detection_repository_sanitizes_object_id_values():
    class FakeCursor:
        def __init__(self, docs):
            self._docs = docs

        def __aiter__(self):
            async def _gen():
                for doc in self._docs:
                    yield doc

            return _gen()

    class FakeCollection:
        def __init__(self, docs):
            self._docs = docs

        def find(self, filter):
            return FakeCursor(self._docs)

    class DummyDatabase:
        def __init__(self, collection):
            self._collection = collection

        def __getitem__(self, name):
            return self._collection

    raw_doc = {
        "_id": ObjectId(),
        "detection_id": "d-1",
        "upload_id": "u-1",
        "source_ip": "10.0.0.1",
        "detection_type": "sql_injection",
        "severity": "high",
        "confidence": 0.9,
        "details": {
            "inner_id": ObjectId(),
            "description": "payload",
        },
        "generated_at": "2026-06-07T10:00:00Z",
    }

    repository = DetectionRepository(DummyDatabase(FakeCollection([raw_doc])))
    sanitized = await repository.find_by_upload_id("u-1")

    assert len(sanitized) == 1
    assert "_id" not in sanitized[0]
    assert isinstance(sanitized[0]["details"]["inner_id"], str)


def test_base_repository_sanitize_document_handles_object_ids():
    raw_doc = {
        "_id": ObjectId(),
        "nested": {
            "object_id": ObjectId(),
            "array": [ObjectId(), {"inner": ObjectId()}],
        },
    }

    sanitized = BaseRepository.sanitize_document(raw_doc)

    assert "_id" not in sanitized
    assert isinstance(sanitized["nested"]["object_id"], str)
    assert isinstance(sanitized["nested"]["array"][0], str)
    assert isinstance(sanitized["nested"]["array"][1]["inner"], str)
