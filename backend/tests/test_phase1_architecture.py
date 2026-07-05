from app.models.security_catalog import SECURITY_RULE_CATALOG
from app.models.upload import UploadStatus
from app.services.detection_engine import Detection, DetectionEngine
from app.services.mitre_mapper import MitreMapper
from app.services.risk_scoring_engine import RiskScoringEngine
from app.services.timeline_builder import TimelineBuilder

from tests.support.in_memory_upload_repository import InMemoryUploadRepository


def test_security_services_use_canonical_catalog() -> None:
    detections = DetectionEngine().detect(
        [{"upload_id": "u-1", "source_ip": "10.0.0.1", "sqli_attempt_count": 1}]
    )
    detection = detections[0]
    metadata = SECURITY_RULE_CATALOG[detection.detection_type]

    assert detection.severity == metadata.severity
    assert MitreMapper().map_detection(detection) == list(metadata.mitre_techniques)
    assert RiskScoringEngine.WEIGHTS[detection.detection_type] == metadata.risk_weight


def test_timeline_order_is_independent_of_detection_order() -> None:
    detections = [
        Detection(
            upload_id="u-1",
            source_ip="10.0.0.1",
            detection_type="webshell_activity",
            severity="critical",
        ),
        Detection(
            upload_id="u-1",
            source_ip="10.0.0.1",
            detection_type="sql_injection",
            severity="high",
        ),
        Detection(
            upload_id="u-1",
            source_ip="10.0.0.1",
            detection_type="reconnaissance",
            severity="low",
        ),
    ]

    assert TimelineBuilder().build_attack_chain(detections) == [
        "reconnaissance",
        "initial_access",
        "persistence",
    ]


async def test_upload_transition_is_compare_and_set() -> None:
    repository = InMemoryUploadRepository()
    upload = await repository.create_pending(
        original_name="events.log", stored_filename="events.log", size_bytes=10
    )

    claimed = await repository.transition_status(
        upload["upload_id"],
        expected={UploadStatus.PENDING},
        target=UploadStatus.UPLOADED,
    )
    stale_claim = await repository.transition_status(
        upload["upload_id"],
        expected={UploadStatus.PENDING},
        target=UploadStatus.UPLOADED,
    )

    assert claimed is not None
    assert stale_claim is None
