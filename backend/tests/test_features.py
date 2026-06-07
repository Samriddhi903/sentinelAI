import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_extract_features_endpoint_persists_features_and_updates_status(
    app, upload_dir, client_upload_with_event_repo
) -> None:
    client, upload_repo, event_repo = client_upload_with_event_repo

    # upload a sample nginx line to produce events
    content = b'192.168.1.1 - - [03/Jun/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 612 "-" "curl/7.68.0"'

    response = await client.post(
        "/api/v1/upload",
        files={"file": ("nginx.log", content, "text/plain")},
    )

    assert response.status_code == 201
    upload_id = response.json()["upload_id"]

    # process and normalize to create events
    proc = await client.post(f"/api/v1/upload/{upload_id}/process")
    assert proc.status_code == 200
    assert proc.json()["status"] == "processed"

    norm = await client.post(f"/api/v1/upload/{upload_id}/normalize")
    assert norm.status_code == 200

    # now attach an in-memory feature repo and the feature service
    from app.dependencies import get_feature_engineering_service
    from tests.support.in_memory_feature_repository import InMemoryFeatureRepository

    feature_repo = InMemoryFeatureRepository()

    def feature_repo_factory():
        return feature_repo

    # override provider
    app.dependency_overrides[get_feature_engineering_service] = lambda upload_repository=None, event_repository=None, feature_repository=None: __import__(
        "app.services.feature_engineering_service", fromlist=["FeatureEngineeringService"]
    ).FeatureEngineeringService(upload_repository=upload_repo, event_repository=event_repo, feature_repository=feature_repo)

    # trigger feature extraction via endpoint
    feat = await client.post(f"/api/v1/upload/{upload_id}/features")
    assert feat.status_code == 200

    # features persisted
    assert len(feature_repo.features) >= 1

    # upload status updated
    stored = upload_repo.documents[upload_id]
    assert stored["status"] == "features_generated"


@pytest.mark.asyncio
async def test_feature_aggregation_and_error_rate_calculation() -> None:
    from datetime import datetime, UTC
    from app.services.feature_engineering_service import FeatureEngineeringService
    from tests.support.in_memory_event_repository import InMemoryEventRepository
    from tests.support.in_memory_upload_repository import InMemoryUploadRepository
    from tests.support.in_memory_feature_repository import InMemoryFeatureRepository
    from app.models.upload import UploadStatus

    upload_repo = InMemoryUploadRepository()
    event_repo = InMemoryEventRepository()
    feature_repo = InMemoryFeatureRepository()

    # create upload doc
    doc = await upload_repo.create_pending(original_name="f", stored_filename="f", size_bytes=1)
    upload_id = doc["upload_id"]
    # mark normalized
    await upload_repo.update_normalization_result(upload_id, status=UploadStatus.NORMALIZED, normalized_at=datetime.now(UTC))

    # insert events for two IPs with various status codes
    events = [
        {"upload_id": upload_id, "ip": "1.1.1.1", "metadata": {"path": "/a", "status_code": "200"}},
        {"upload_id": upload_id, "ip": "1.1.1.1", "metadata": {"path": "/b", "status_code": "404"}},
        {"upload_id": upload_id, "ip": "2.2.2.2", "metadata": {"path": "/a", "status_code": "500"}},
    ]
    await event_repo.insert_events(events)

    service = FeatureEngineeringService(upload_repo, event_repo, feature_repo)
    result = await service.extract_features(upload_id)

    assert result["status"] == "features_generated"
    # two feature docs expected
    assert len(feature_repo.features) == 2

    f1 = next(f for f in feature_repo.features if f["source_ip"] == "1.1.1.1")
    assert f1["request_count"] == 2
    assert f1["status_2xx"] == 1
    assert f1["status_4xx"] == 1
    assert f1["error_rate"] == pytest.approx(1 / 2)

def test_syslog_parser_extracts_ip_from_message() -> None:
    from app.parsers.syslog_parser import SyslogParser

    parser = SyslogParser()
    sample = "Jun 3 10:20:16 host sshd: Failed password for invalid user admin from 192.168.1.10"

    normalized = parser.normalize(parser.parse(sample))
    assert normalized[0]["ip"] == "192.168.1.10"

    sample2 = "Jun 3 10:21:01 host kernel: [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=203.0.113.5 DST=10.0.0.1"
    normalized2 = parser.normalize(parser.parse(sample2))
    assert normalized2[0]["ip"] == "203.0.113.5"


@pytest.mark.asyncio
async def test_feature_generation_creates_feature_per_source_ip() -> None:
    from datetime import datetime, UTC
    from app.services.feature_engineering_service import FeatureEngineeringService
    from tests.support.in_memory_event_repository import InMemoryEventRepository
    from tests.support.in_memory_upload_repository import InMemoryUploadRepository
    from tests.support.in_memory_feature_repository import InMemoryFeatureRepository
    from app.models.upload import UploadStatus

    upload_repo = InMemoryUploadRepository()
    event_repo = InMemoryEventRepository()
    feature_repo = InMemoryFeatureRepository()
    doc = await upload_repo.create_pending(original_name="m", stored_filename="m", size_bytes=1)
    upload_id = doc["upload_id"]
    await upload_repo.update_normalization_result(upload_id, status=UploadStatus.NORMALIZED, normalized_at=datetime.now(UTC))

    events = [
        {"upload_id": upload_id, "ip": "192.168.1.10", "event_type": "http_request", "metadata": {"path": "/dashboard", "status_code": "200"}},
        {"upload_id": upload_id, "ip": "192.168.1.55", "event_type": "http_request", "metadata": {"path": "/login", "status_code": "401"}},
        {"upload_id": upload_id, "ip": "203.0.113.5", "event_type": "http_request", "metadata": {"path": "/wp-admin", "status_code": "404"}},
    ]
    await event_repo.insert_events(events)

    service = FeatureEngineeringService(upload_repo, event_repo, feature_repo)
    result = await service.extract_features(upload_id)

    assert result["status"] == "features_generated"
    assert len(feature_repo.features) == 3
    assert {f["source_ip"] for f in feature_repo.features} == {"192.168.1.10", "192.168.1.55", "203.0.113.5"}


@pytest.mark.asyncio
async def test_json_security_events_count_failed_login_and_port_scan() -> None:
    from datetime import datetime, UTC
    from app.services.feature_engineering_service import FeatureEngineeringService
    from tests.support.in_memory_event_repository import InMemoryEventRepository
    from tests.support.in_memory_upload_repository import InMemoryUploadRepository
    from tests.support.in_memory_feature_repository import InMemoryFeatureRepository
    from app.models.upload import UploadStatus

    upload_repo = InMemoryUploadRepository()
    event_repo = InMemoryEventRepository()
    feature_repo = InMemoryFeatureRepository()
    doc = await upload_repo.create_pending(original_name="j", stored_filename="j", size_bytes=1)
    upload_id = doc["upload_id"]
    await upload_repo.update_normalization_result(upload_id, status=UploadStatus.NORMALIZED, normalized_at=datetime.now(UTC))

    events = [
        {"upload_id": upload_id, "ip": "10.1.1.1", "event_type": "failed_login", "metadata": {"user": "admin"}},
        {"upload_id": upload_id, "ip": "10.1.1.1", "event_type": "port_scan", "metadata": {"target": "22"}},
        {"upload_id": upload_id, "ip": "10.1.1.1", "event_type": "successful_login", "metadata": {"user": "admin"}},
    ]
    await event_repo.insert_events(events)

    service = FeatureEngineeringService(upload_repo, event_repo, feature_repo)
    result = await service.extract_features(upload_id)

    assert result["status"] == "features_generated"
    assert len(feature_repo.features) == 1
    feature = feature_repo.features[0]
    assert feature["failed_login_count"] == 1
    assert feature["successful_login_count"] == 1
    assert feature["port_scan_count"] == 1


@pytest.mark.asyncio
async def test_mixed_event_types_create_multiple_feature_vectors() -> None:
    from datetime import datetime, UTC
    from app.services.feature_engineering_service import FeatureEngineeringService
    from tests.support.in_memory_event_repository import InMemoryEventRepository
    from tests.support.in_memory_upload_repository import InMemoryUploadRepository
    from tests.support.in_memory_feature_repository import InMemoryFeatureRepository
    from app.models.upload import UploadStatus

    upload_repo = InMemoryUploadRepository()
    event_repo = InMemoryEventRepository()
    feature_repo = InMemoryFeatureRepository()
    doc = await upload_repo.create_pending(original_name="x", stored_filename="x", size_bytes=1)
    upload_id = doc["upload_id"]
    await upload_repo.update_normalization_result(upload_id, status=UploadStatus.NORMALIZED, normalized_at=datetime.now(UTC))

    events = [
        {"upload_id": upload_id, "ip": "192.168.1.10", "event_type": "http_request", "metadata": {"path": "/dashboard", "status_code": "200"}},
        {"upload_id": upload_id, "ip": "10.0.0.5", "event_type": "syslog_event", "metadata": {"message": "Failed password for invalid user admin from 10.0.0.5"}},
        {"upload_id": upload_id, "ip": "10.0.0.5", "event_type": "port_scan", "metadata": {"details": "scan detected"}},
    ]
    await event_repo.insert_events(events)

    service = FeatureEngineeringService(upload_repo, event_repo, feature_repo)
    result = await service.extract_features(upload_id)

    assert result["status"] == "features_generated"
    assert len(feature_repo.features) == 2
    assert {f["source_ip"] for f in feature_repo.features} == {"192.168.1.10", "10.0.0.5"}
    syslog_feature = next(f for f in feature_repo.features if f["source_ip"] == "10.0.0.5")
    assert syslog_feature["failed_login_count"] == 1
    assert syslog_feature["port_scan_count"] == 1

@pytest.mark.asyncio
async def test_syslog_feature_extraction_counts() -> None:
    from datetime import datetime, UTC
    from app.services.feature_engineering_service import FeatureEngineeringService
    from tests.support.in_memory_event_repository import InMemoryEventRepository
    from tests.support.in_memory_upload_repository import InMemoryUploadRepository
    from tests.support.in_memory_feature_repository import InMemoryFeatureRepository
    from app.models.upload import UploadStatus

    upload_repo = InMemoryUploadRepository()
    event_repo = InMemoryEventRepository()
    feature_repo = InMemoryFeatureRepository()

    # create upload doc and mark normalized
    doc = await upload_repo.create_pending(original_name="s", stored_filename="s", size_bytes=1)
    upload_id = doc["upload_id"]
    await upload_repo.update_normalization_result(upload_id, status=UploadStatus.NORMALIZED, normalized_at=datetime.now(UTC))

    # insert syslog events across two source IPs
    events = [
        {"upload_id": upload_id, "ip": "10.0.0.1", "event_type": "syslog_event", "metadata": {"message": "Failed password for invalid user"}},
        {"upload_id": upload_id, "ip": "10.0.0.1", "event_type": "syslog_event", "metadata": {"message": "Accepted password for user"}},
        {"upload_id": upload_id, "ip": "10.0.0.2", "event_type": "syslog_event", "metadata": {"message": "sudo:     john : TTY=pts/1 ; PWD=/home/john ; USER=root ; COMMAND=/bin/ls"}},
        {"upload_id": upload_id, "ip": "10.0.0.2", "event_type": "syslog_event", "metadata": {"message": "UFW BLOCK IN=... SRC=192.168.0.5"}},
    ]
    await event_repo.insert_events(events)

    service = FeatureEngineeringService(upload_repo, event_repo, feature_repo)
    result = await service.extract_features(upload_id)

    assert result["status"] == "features_generated"
    # two feature docs expected (per IP)
    assert len(feature_repo.features) == 2

    f_a = next(f for f in feature_repo.features if f["source_ip"] == "10.0.0.1")
    assert f_a.get("failed_login_count", 0) == 1
    assert f_a.get("successful_login_count", 0) == 1

    f_b = next(f for f in feature_repo.features if f["source_ip"] == "10.0.0.2")
    assert f_b.get("sudo_event_count", 0) == 1
    assert f_b.get("firewall_block_count", 0) == 1

    # unique_source_ips should reflect 2 distinct IPs across events
    assert all(f.get("unique_source_ips", 0) == 2 for f in feature_repo.features)


def test_syslog_sample_sudo_attributed_to_attacker_ip() -> None:
    """Sudo events without embedded IPs should correlate to the prior remote login IP."""
    from pathlib import Path

    from app.feature_extractors.syslog import SyslogFeatureExtractor
    from app.parsers.syslog_parser import SyslogParser

    sample_path = Path(__file__).resolve().parents[2] / "samples" / "syslog.log"
    parser = SyslogParser()
    normalized = parser.normalize(parser.parse(sample_path.read_text(encoding="utf-8")))

    sudo_event = next(
        e for e in normalized if (e.get("metadata") or {}).get("process") == "sudo"
    )
    assert sudo_event["ip"] is None
    assert sudo_event["user"] == "attacker"
    assert "sudo" not in (sudo_event["metadata"]["message"]).lower()

    features = SyslogFeatureExtractor().extract(normalized)
    attacker = next(f for f in features if f["source_ip"] == "198.51.100.100")

    assert attacker["sudo_event_count"] == 1
    assert attacker["new_user_count"] == 1
    assert attacker["password_change_count"] == 1
    assert attacker["suspicious_cron_count"] == 1
    assert attacker["failed_login_count"] == 5
