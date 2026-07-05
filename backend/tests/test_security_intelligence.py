import pytest

from app.services.detection_engine import DetectionEngine
from app.services.investigation_service import InvestigationService
from app.services.mitre_mapper import MitreMapper
from app.services.risk_scoring_engine import RiskScoringEngine
from app.services.timeline_builder import TimelineBuilder


class InMemoryInvestigationRepository:
    def __init__(self) -> None:
        self.documents: list[dict[str, object]] = []

    async def insert_investigations(self, investigations: list[dict[str, object]]) -> None:
        self.documents.extend(investigations)


@pytest.fixture
def detection_engine() -> DetectionEngine:
    return DetectionEngine()


def test_detection_engine_produces_supported_detections(detection_engine: DetectionEngine):
    features = [
        {
            "upload_id": "upload-123",
            "source_ip": "198.51.100.50",
            "sqli_attempt_count": 1,
            "xss_attempt_count": 1,
            "directory_enumeration_count": 3,
            "sensitive_file_probe_count": 1,
            "path_traversal_count": 1,
            "webshell_access_count": 1,
            "brute_force_attempt_count": 5,
            "failed_login_count": 5,
            # privilege_escalation_count alone is not sufficient anymore;
            # include sudo + suspicious context.
            "sudo_event_count": 1,
            "privilege_escalation_count": 0,
            "new_user_count": 0,
            "password_change_count": 0,
            "suspicious_cron_count": 1,

            "reconnaissance_count": 1,
            "critical_file_modification_count": 1,
        }
    ]

    detections = detection_engine.detect(features)
    detection_types = {d.detection_type for d in detections}

    assert detection_types == {
        "sql_injection",
        "xss",
        "directory_enumeration",
        "sensitive_file_discovery",
        "path_traversal",
        "webshell_activity",
        "brute_force",
        "privilege_escalation",
        "reconnaissance",
        "suspicious_cron",
        "critical_file_modification",
    }


def test_risk_scoring_engine_clamps_score_and_assigns_critical_severity():
    engine = RiskScoringEngine()
    features = [
        {
            "upload_id": "upload-123",
            "source_ip": "198.51.100.50",
            "sqli_attempt_count": 1,
            "webshell_access_count": 1,
            "privilege_escalation_count": 1,
        }
    ]

    detections = DetectionEngine().detect(features)
    assessment = engine.score_detections(detections)

    # With only privilege_escalation_count (no sudo + suspicious context),
    # privilege_escalation should not be detected.
    assert assessment.score == 85
    assert assessment.severity.value == "critical"
    assert assessment.upload_id == "upload-123"
    assert assessment.source_ip == "198.51.100.50"
    # privilege_escalation should not be present without sudo + suspicious context.
    assert set(assessment.detection_types) == {"sql_injection", "webshell_activity"}


def test_risk_scoring_engine_weights_account_and_credential_modifications():
    engine = RiskScoringEngine()
    features = [
        {
            "upload_id": "upload-888",
            "source_ip": "198.51.100.88",
            "new_user_count": 1,
            "password_change_count": 1,
        }
    ]

    detections = DetectionEngine().detect(features)
    assessment = engine.score_detections(detections)

    assert {d.detection_type for d in detections} == {"account_creation", "credential_modification"}
    assert assessment.score == 70
    assert assessment.severity.value == "high"


def test_mitre_mapper_returns_expected_techniques():
    mapper = MitreMapper()
    features = [
        {
            "upload_id": "upload-999",
            "source_ip": "203.0.113.10",
            "sqli_attempt_count": 1,
            "brute_force_attempt_count": 5,
            "reconnaissance_count": 1,
        }
    ]

    detections = DetectionEngine().detect(features)
    techniques = mapper.map_detections(detections)

    assert "T1190" in techniques
    assert "T1110" in techniques
    assert "T1046" in techniques


def test_timeline_builder_creates_ordered_attack_chain():
    engine = DetectionEngine()
    # privilege_escalation now requires sudo + suspicious context.
    # Keep brute force / auth-abuse indicators and add sudo + post-exploitation indicators
    # so timeline remains stable.
    features = [
        {
            "upload_id": "upload-444",
            "source_ip": "198.51.100.60",
            "failed_login_count": 5,
            "sudo_event_count": 1,
            "new_user_count": 1,
            "password_change_count": 1,
            "suspicious_cron_count": 1,
            "critical_file_modification_count": 1,
        }
    ]

    detections = engine.detect(features)
    timeline = TimelineBuilder().build_attack_chain(detections)

    assert timeline == ["authentication_abuse", "privilege_escalation", "persistence"]


@pytest.mark.asyncio
async def test_investigation_service_generates_and_persists_document():
    repository = InMemoryInvestigationRepository()
    service = InvestigationService(
        repository=repository,
        risk_engine=RiskScoringEngine(),
        timeline_builder=TimelineBuilder(),
        mitre_mapper=MitreMapper(),
    )

    features = [
        {
            "upload_id": "upload-555",
            "source_ip": "198.51.100.22",
            "sqli_attempt_count": 1,
            "webshell_access_count": 1,
        }
    ]
    detections = DetectionEngine().detect(features)
    investigation = await service.create_investigation(detections)

    assert investigation.upload_id == "upload-555"
    assert investigation.source_ip == "198.51.100.22"
    assert investigation.incident_type == "Web Application Compromise"
    assert investigation.severity.value == "critical"
    assert investigation.risk_score == 85
    assert "T1190" in investigation.mitre_techniques
    assert "T1505" in investigation.mitre_techniques
    assert investigation.attack_chain == ["initial_access", "persistence"]
    assert len(repository.documents) == 1


@pytest.mark.asyncio
async def test_investigation_service_uses_incident_classifier_for_account_compromise():
    repository = InMemoryInvestigationRepository()
    service = InvestigationService(
        repository=repository,
        risk_engine=RiskScoringEngine(),
        timeline_builder=TimelineBuilder(),
        mitre_mapper=MitreMapper(),
    )

    features = [
        {
            "upload_id": "upload-777",
            "source_ip": "198.51.100.77",
            "failed_login_count": 5,
            "sudo_event_count": 1,
        }
    ]
    detections = DetectionEngine().detect(features)
    investigation = await service.create_investigation(detections)

    assert investigation.incident_type == "Account Compromise"
    assert "T1110" in investigation.mitre_techniques
    assert "T1068" in investigation.mitre_techniques


@pytest.mark.asyncio
async def test_investigation_service_uses_incident_classifier_for_persistence_establishment():
    repository = InMemoryInvestigationRepository()
    service = InvestigationService(
        repository=repository,
        risk_engine=RiskScoringEngine(),
        timeline_builder=TimelineBuilder(),
        mitre_mapper=MitreMapper(),
    )

    features = [
        {
            "upload_id": "upload-888",
            "source_ip": "198.51.100.88",
            "sudo_event_count": 1,
            "new_user_count": 1,
            "password_change_count": 1,
        }
    ]
    detections = DetectionEngine().detect(features)
    investigation = await service.create_investigation(detections)

    assert investigation.incident_type == "Persistence Establishment"
    assert "T1068" in investigation.mitre_techniques
    assert "T1136" in investigation.mitre_techniques
    assert "T1098" in investigation.mitre_techniques


@pytest.mark.asyncio
async def test_investigation_service_uses_incident_classifier_for_post_exploitation():
    repository = InMemoryInvestigationRepository()
    service = InvestigationService(
        repository=repository,
        risk_engine=RiskScoringEngine(),
        timeline_builder=TimelineBuilder(),
        mitre_mapper=MitreMapper(),
    )

    features = [
        {
            "upload_id": "upload-999",
            "source_ip": "198.51.100.99",
            "command_execution_count": 1,
            "sensitive_file_access_count": 1,
        }
    ]
    detections = DetectionEngine().detect(features)
    investigation = await service.create_investigation(detections)

    assert investigation.incident_type == "Post-Exploitation Activity"
    assert "T1059" in investigation.mitre_techniques
    assert "T1005" in investigation.mitre_techniques
