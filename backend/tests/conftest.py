"""Shared pytest fixtures."""

import os
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

os.environ.setdefault("MONGODB_URI", "")
os.environ.setdefault("SECRET_KEY", "test-secret-key")
os.environ.setdefault("LOG_FORMAT", "console")

from app.core.config import get_settings
from app.database.connection import DatabaseManager, get_database_manager
from app.dependencies import get_upload_service, get_event_repository, get_event_normalization_service
from app.main import create_app
from app.services.file_storage_service import FileStorageService
from app.services.upload_service import UploadService
from app.services.upload_validator import UploadValidator
from tests.support.in_memory_upload_repository import InMemoryUploadRepository
from tests.support.in_memory_event_repository import InMemoryEventRepository


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
    if ping_result:
        manager._database = AsyncMock()
    return manager


@pytest.fixture
def upload_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("UPLOAD_DIR", str(tmp_path))
    get_settings.cache_clear()
    return tmp_path


@pytest.fixture
def mock_text_mime() -> Iterator[None]:
    with patch(
        "app.services.upload_validator.magic.from_buffer",
        return_value="text/plain",
    ):
        yield


@pytest.fixture
async def client_upload_connected(
    app,
    upload_dir: Path,
) -> AsyncIterator[tuple[AsyncClient, InMemoryUploadRepository]]:
    repository = InMemoryUploadRepository()
    db_manager = build_db_manager(ping_result=True)
    settings = get_settings()

    def upload_service_factory() -> UploadService:
        return UploadService(
            db_manager=db_manager,
            upload_repository=repository,
            file_storage=FileStorageService(settings),
            upload_validator=UploadValidator(settings),
        )

    app.dependency_overrides[get_upload_service] = upload_service_factory
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as http_client:
        yield http_client, repository
    app.dependency_overrides.clear()


@pytest.fixture
async def client_upload_with_event_repo(app, upload_dir: Path) -> AsyncIterator[tuple[AsyncClient, InMemoryUploadRepository, InMemoryEventRepository]]:
    upload_repository = InMemoryUploadRepository()
    event_repository = InMemoryEventRepository()
    db_manager = build_db_manager(ping_result=True)
    settings = get_settings()

    def upload_service_factory() -> UploadService:
        return UploadService(
            db_manager=db_manager,
            upload_repository=upload_repository,
            file_storage=FileStorageService(settings),
            upload_validator=UploadValidator(settings),
        )

    def event_repo_factory():
        return event_repository

    # build a parser registry for the normalizer
    from app.parsers.registry import ParserRegistry
    from app.parsers.nginx_parser import NginxParser
    from app.parsers.apache_parser import ApacheParser
    from app.parsers.syslog_parser import SyslogParser
    from app.parsers.json_log_parser import JsonLogParser
    from app.services.event_normalization_service import EventNormalizationService

    registry = ParserRegistry()
    registry.register_parser(NginxParser())
    registry.register_parser(ApacheParser())
    registry.register_parser(SyslogParser())
    registry.register_parser(JsonLogParser())

    def event_normalizer_factory() -> EventNormalizationService:
        settings = get_settings()
        return EventNormalizationService(
            upload_repository=upload_repository,
            event_repository=event_repository,
            file_storage=FileStorageService(settings),
            parser_registry=registry,
        )

    # override upload service and event normalization provider
    app.dependency_overrides[get_upload_service] = upload_service_factory
    app.dependency_overrides[get_event_repository] = event_repo_factory
    app.dependency_overrides[get_event_normalization_service] = event_normalizer_factory

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as http_client:
        yield http_client, upload_repository, event_repository

    app.dependency_overrides.clear()


@pytest.fixture
async def client_upload_disconnected(app, upload_dir: Path) -> AsyncIterator[AsyncClient]:
    db_manager = build_db_manager(ping_result=False)
    settings = get_settings()
    repository = InMemoryUploadRepository()

    app.dependency_overrides[get_upload_service] = lambda: UploadService(
        db_manager=db_manager,
        upload_repository=repository,
        file_storage=FileStorageService(settings),
        upload_validator=UploadValidator(settings),
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as http_client:
        yield http_client
    app.dependency_overrides.clear()


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
