"""Integration tests for upload endpoint."""

import pytest
from httpx import AsyncClient

from tests.support.in_memory_upload_repository import InMemoryUploadRepository


@pytest.mark.asyncio
async def test_upload_returns_201_with_uploaded_status(
    client_upload_connected: tuple[AsyncClient, InMemoryUploadRepository],
    upload_dir,
) -> None:
    client, _repository = client_upload_connected
    content = b"192.168.1.1 - - [03/Jun/2026:10:00:00 +0000] GET / HTTP/1.1 200"

    response = await client.post(
        "/api/v1/upload",
        files={"file": ("nginx.log", content, "text/plain")},
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["status"] == "uploaded"
    assert payload["original_name"] == "nginx.log"
    assert payload["size_bytes"] == len(content)
    assert payload["upload_id"]
    assert payload["filename"].endswith(".log")
    assert list(upload_dir.iterdir())


@pytest.mark.asyncio
async def test_upload_returns_503_when_database_unavailable(
    client_upload_disconnected: AsyncClient,
    mock_text_mime,
) -> None:
    response = await client_upload_disconnected.post(
        "/api/v1/upload",
        files={"file": ("nginx.log", b"log line", "text/plain")},
    )

    assert response.status_code == 503
    payload = response.json()
    assert payload["code"] == "DATABASE_UNAVAILABLE"
    assert payload["detail"] == "Database unavailable — cannot accept uploads"


@pytest.mark.asyncio
async def test_upload_returns_structured_validation_error(
    client_upload_connected: tuple[AsyncClient, InMemoryUploadRepository],
) -> None:
    client, _repository = client_upload_connected

    response = await client.post(
        "/api/v1/upload",
        files={"file": ("script.exe", b"MZ", "application/octet-stream")},
    )

    assert response.status_code == 400
    payload = response.json()
    assert payload["code"] == "INVALID_EXTENSION"
    assert "detail" in payload


@pytest.mark.asyncio
async def test_upload_persists_pending_then_uploaded_status(
    client_upload_connected: tuple[AsyncClient, InMemoryUploadRepository],
) -> None:
    client, repository = client_upload_connected

    response = await client.post(
        "/api/v1/upload",
        files={"file": ("access.log", b"event line", "text/plain")},
    )

    upload_id = response.json()["upload_id"]
    stored = repository.documents[upload_id]
    assert stored["status"] == "uploaded"
