"""FastAPI dependency injection providers."""

from typing import Annotated

from fastapi import Depends

from app.core.config import Settings, get_settings
from app.core.exceptions import DatabaseUnavailableError
from app.database.connection import DatabaseManager, get_database_manager
from app.repositories.upload_repository import UploadRepository
from app.services.file_storage_service import FileStorageService
from app.services.health_service import HealthService
from app.services.upload_service import UploadService
from app.services.upload_validator import UploadValidator
from app.services.format_detection_service import FormatDetectionService
from app.parsers.registry import ParserRegistry
from app.parsers.nginx_parser import NginxParser
from app.parsers.apache_parser import ApacheParser
from app.parsers.syslog_parser import SyslogParser
from app.parsers.json_log_parser import JsonLogParser
from app.repositories.event_repository import EventRepository
from app.services.event_normalization_service import EventNormalizationService

SettingsDep = Annotated[Settings, Depends(get_settings)]
DatabaseManagerDep = Annotated[DatabaseManager, Depends(get_database_manager)]


def get_health_service(
    settings: SettingsDep,
    db_manager: DatabaseManagerDep,
) -> HealthService:
    return HealthService(settings=settings, db_manager=db_manager)


HealthServiceDep = Annotated[HealthService, Depends(get_health_service)]


def get_upload_repository(db_manager: DatabaseManagerDep) -> UploadRepository:
    if db_manager.database is None:
        raise DatabaseUnavailableError()
    return UploadRepository(db_manager.database)


UploadRepositoryDep = Annotated[UploadRepository, Depends(get_upload_repository)]


def get_file_storage_service(settings: SettingsDep) -> FileStorageService:
    return FileStorageService(settings)


FileStorageServiceDep = Annotated[FileStorageService, Depends(get_file_storage_service)]


def get_upload_validator(settings: SettingsDep) -> UploadValidator:
    return UploadValidator(settings)


UploadValidatorDep = Annotated[UploadValidator, Depends(get_upload_validator)]


def get_parser_registry() -> ParserRegistry:
    registry = ParserRegistry()
    registry.register_parser(NginxParser())
    registry.register_parser(ApacheParser())
    registry.register_parser(SyslogParser())
    registry.register_parser(JsonLogParser())
    return registry


ParserRegistryDep = Annotated[ParserRegistry, Depends(get_parser_registry)]


def get_upload_service(
    db_manager: DatabaseManagerDep,
    upload_repository: UploadRepositoryDep,
    file_storage: FileStorageServiceDep,
    upload_validator: UploadValidatorDep,
    parser_registry: ParserRegistryDep,
) -> UploadService:
    detection_service = FormatDetectionService(parser_registry)

    return UploadService(
        db_manager=db_manager,
        upload_repository=upload_repository,
        file_storage=file_storage,
        upload_validator=upload_validator,
        format_detection_service=detection_service,
    )


UploadServiceDep = Annotated[UploadService, Depends(get_upload_service)]


def get_event_repository(db_manager: DatabaseManagerDep) -> EventRepository:
    if db_manager.database is None:
        raise DatabaseUnavailableError()
    return EventRepository(db_manager.database)


EventRepositoryDep = Annotated[EventRepository, Depends(get_event_repository)]


def get_event_normalization_service(
    upload_repository: UploadRepositoryDep,
    event_repository: EventRepositoryDep,
    file_storage: FileStorageServiceDep,
    parser_registry: ParserRegistryDep,
) -> EventNormalizationService:
    return EventNormalizationService(
        upload_repository=upload_repository,
        event_repository=event_repository,
        file_storage=file_storage,
        parser_registry=parser_registry,
    )


EventNormalizationServiceDep = Annotated[EventNormalizationService, Depends(get_event_normalization_service)]
