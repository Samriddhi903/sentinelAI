"""Tests for readiness health endpoint."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_readiness_returns_200_when_mongodb_connected(
    client_db_connected: AsyncClient,
) -> None:
    response = await client_db_connected.get("/api/v1/health/ready")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ready"
    assert payload["mongodb"] == "connected"


@pytest.mark.asyncio
async def test_readiness_returns_503_when_mongodb_disconnected(
    client_db_disconnected: AsyncClient,
) -> None:
    response = await client_db_disconnected.get("/api/v1/health/ready")

    assert response.status_code == 503
    payload = response.json()
    assert payload["status"] == "not_ready"
    assert payload["mongodb"] == "disconnected"
