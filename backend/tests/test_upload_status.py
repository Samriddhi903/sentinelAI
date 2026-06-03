"""Tests for upload status polling endpoint."""

import pytest
from httpx import AsyncClient

from tests.support.in_memory_upload_repository import InMemoryUploadRepository


@pytest.mark.asyncio
async def test_get_upload_status_returns_current_state(
    client_upload_connected: tuple[AsyncClient, InMemoryUploadRepository],
) -> None:
    client, _repository = client_upload_connected

    upload_response = await client.post(
        "/api/v1/upload",
        files={"file": ("access.log", b"event line", "text/plain")},
    )
    upload_id = upload_response.json()["upload_id"]

    response = await client.get(f"/api/v1/upload/{upload_id}/status")

    assert response.status_code == 200
    payload = response.json()
    assert payload["upload_id"] == upload_id
    assert payload["status"] == "uploaded"
    assert payload["format"] is None
    assert payload["confidence"] is None
    assert payload["processed_at"] is None


@pytest.mark.asyncio
async def test_get_upload_status_returns_404_for_unknown_id(
    client_upload_connected: tuple[AsyncClient, InMemoryUploadRepository],
) -> None:
    client, _repository = client_upload_connected

    response = await client.get("/api/v1/upload/00000000-0000-0000-0000-000000000000/status")

    assert response.status_code == 404
    payload = response.json()
    assert payload["code"] == "UPLOAD_NOT_FOUND"


@pytest.mark.asyncio
async def test_get_upload_status_returns_503_when_database_unavailable(
    client_upload_disconnected: AsyncClient,
) -> None:
    response = await client_upload_disconnected.get(
        "/api/v1/upload/00000000-0000-0000-0000-000000000000/status",
    )

    assert response.status_code == 503
    payload = response.json()
    assert payload["code"] == "DATABASE_UNAVAILABLE"
