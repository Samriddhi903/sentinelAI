"""Shared pytest fixtures."""

import os
from collections.abc import AsyncIterator
from unittest.mock import AsyncMock

import pytest
from httpx import ASGITransport, AsyncClient

os.environ.setdefault("MONGODB_URI", "")
os.environ.setdefault("SECRET_KEY", "test-secret-key")
os.environ.setdefault("LOG_FORMAT", "console")

from app.core.config import get_settings
from app.database.connection import DatabaseManager, get_database_manager
from app.main import create_app


@pytest.fixture(autouse=True)
def reset_settings_cache() -> None:
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def app():
    return create_app()


@pytest.fixture
async def client(app) -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as http_client:
        yield http_client


def build_db_manager(*, ping_result: bool) -> DatabaseManager:
    manager = DatabaseManager()
    manager.ping = AsyncMock(return_value=ping_result)
    return manager


@pytest.fixture
async def client_db_connected(app) -> AsyncIterator[AsyncClient]:
    app.dependency_overrides[get_database_manager] = lambda: build_db_manager(ping_result=True)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as http_client:
        yield http_client
    app.dependency_overrides.clear()


@pytest.fixture
async def client_db_disconnected(app) -> AsyncIterator[AsyncClient]:
    app.dependency_overrides[get_database_manager] = lambda: build_db_manager(ping_result=False)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as http_client:
        yield http_client
    app.dependency_overrides.clear()
