"""MongoDB connection manager with degraded startup support."""

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from app.core.logging import get_logger

logger = get_logger(__name__)


class DatabaseManager:
    """Manages the Motor client lifecycle without blocking application startup."""

    def __init__(self) -> None:
        self._client: AsyncIOMotorClient | None = None
        self._database: AsyncIOMotorDatabase | None = None
        self._db_name: str = "sentinelai"

    @property
    def is_configured(self) -> bool:
        return self._client is not None

    @property
    def database(self) -> AsyncIOMotorDatabase | None:
        return self._database

    async def connect(self, uri: str, db_name: str) -> None:
        """Attempt MongoDB connection; log and continue on failure."""
        self._db_name = db_name

        if not uri.strip():
            logger.warning("MONGODB_URI is not set; running in degraded mode")
            return

        try:
            self._client = AsyncIOMotorClient(uri, serverSelectionTimeoutMS=5000)
            await self._client.admin.command("ping")
            self._database = self._client[db_name]
            logger.info("MongoDB connection established", extra={"database": db_name})
        except Exception as exc:
            logger.warning(
                "MongoDB connection failed; application running in degraded mode",
                extra={"error": str(exc)},
            )
            await self.disconnect()

    async def disconnect(self) -> None:
        """Close the MongoDB client if open."""
        if self._client is not None:
            self._client.close()
        self._client = None
        self._database = None

    async def ping(self) -> bool:
        """Return True when MongoDB responds to a ping command."""
        if self._client is None:
            return False

        try:
            await self._client.admin.command("ping")
            if self._database is None:
                self._database = self._client[self._db_name]
            return True
        except Exception as exc:
            logger.warning("MongoDB ping failed", extra={"error": str(exc)})
            return False


_db_manager = DatabaseManager()


def get_database_manager() -> DatabaseManager:
    """Return the singleton database manager."""
    return _db_manager
