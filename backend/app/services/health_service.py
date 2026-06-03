"""Health check business logic."""

from app.core.config import Settings
from app.database.connection import DatabaseManager
from app.schemas.health import LivenessResponse, ReadinessResponse


class HealthService:
    """Provides liveness and readiness health checks."""

    def __init__(self, settings: Settings, db_manager: DatabaseManager) -> None:
        self._settings = settings
        self._db_manager = db_manager

    def get_liveness(self) -> LivenessResponse:
        return LivenessResponse(
            status="alive",
            version=self._settings.app_version,
        )

    async def get_readiness(self) -> tuple[ReadinessResponse, int]:
        is_connected = await self._db_manager.ping()

        if is_connected:
            return (
                ReadinessResponse(status="ready", mongodb="connected"),
                200,
            )

        return (
            ReadinessResponse(status="not_ready", mongodb="disconnected"),
            503,
        )
