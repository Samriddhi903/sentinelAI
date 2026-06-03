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


def get_upload_service(
    db_manager: DatabaseManagerDep,
    upload_repository: UploadRepositoryDep,
    file_storage: FileStorageServiceDep,
    upload_validator: UploadValidatorDep,
) -> UploadService:
    return UploadService(
        db_manager=db_manager,
        upload_repository=upload_repository,
        file_storage=file_storage,
        upload_validator=upload_validator,
    )


UploadServiceDep = Annotated[UploadService, Depends(get_upload_service)]
