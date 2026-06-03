import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_normalize_upload_creates_events_and_updates_status(
    client_upload_with_event_repo: tuple[AsyncClient, object, object], upload_dir
) -> None:
    client, upload_repo, event_repo = client_upload_with_event_repo

    content = b'192.168.1.1 - - [03/Jun/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 612 "-" "curl/7.68.0"'

    response = await client.post(
        "/api/v1/upload",
        files={"file": ("nginx.log", content, "text/plain")},
    )

    assert response.status_code == 201
    upload_id = response.json()["upload_id"]

    # process (detect format)
    proc = await client.post(f"/api/v1/upload/{upload_id}/process")
    assert proc.status_code == 200
    assert proc.json()["status"] == "processed"

    # normalize
    norm = await client.post(f"/api/v1/upload/{upload_id}/normalize")
    assert norm.status_code == 200

    # events persisted
    assert len(event_repo.events) >= 1
    ev = event_repo.events[0]
    assert ev["upload_id"] == upload_id
    assert ev["event_type"] == "http_request"
    assert "metadata" in ev

    # upload status updated
    stored = upload_repo.documents[upload_id]
    assert stored["status"] == "normalized"
    assert stored.get("normalized_at") is not None
