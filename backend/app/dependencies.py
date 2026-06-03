"""FastAPI dependency injection providers."""

from typing import Annotated

from fastapi import Depends

from app.core.config import Settings, get_settings
from app.database.connection import DatabaseManager, get_database_manager
from app.services.health_service import HealthService

SettingsDep = Annotated[Settings, Depends(get_settings)]
DatabaseManagerDep = Annotated[DatabaseManager, Depends(get_database_manager)]


def get_health_service(
    settings: SettingsDep,
    db_manager: DatabaseManagerDep,
) -> HealthService:
    return HealthService(settings=settings, db_manager=db_manager)


HealthServiceDep = Annotated[HealthService, Depends(get_health_service)]
