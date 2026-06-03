import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_process_endpoint_detects_format_and_updates_status(
    client_upload_connected: tuple[AsyncClient, object], upload_dir
) -> None:
    client, repository = client_upload_connected

    content = b'192.168.1.1 - - [03/Jun/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 612'

    response = await client.post(
        "/api/v1/upload",
        files={"file": ("nginx.log", content, "text/plain")},
    )

    assert response.status_code == 201
    upload_id = response.json()["upload_id"]

    proc = await client.post(f"/api/v1/upload/{upload_id}/process")
    assert proc.status_code == 200
    payload = proc.json()
    assert payload["status"] == "processed"
    assert payload["format"] in ("nginx", "apache", None)
    assert payload["confidence"] is not None

    stored = repository.documents[upload_id]
    assert stored["status"] == "processed"
    assert stored["processed_at"] is not None
