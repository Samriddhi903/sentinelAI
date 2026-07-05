"""Base repository providing shared MongoDB collection access."""

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorCollection, AsyncIOMotorDatabase


class BaseRepository:
    """Base class for MongoDB repositories."""

    def __init__(self, database: AsyncIOMotorDatabase, collection_name: str) -> None:
        self._collection: AsyncIOMotorCollection = database[collection_name]

    @property
    def collection(self) -> AsyncIOMotorCollection:
        return self._collection

    @staticmethod
    def sanitize_document(document: dict[str, object]) -> dict[str, object]:
        def clean_value(value: object) -> object:
            if isinstance(value, ObjectId):
                return str(value)
            if isinstance(value, dict):
                return {k: clean_value(v) for k, v in value.items() if k != "_id"}
            if isinstance(value, list):
                return [clean_value(item) for item in value]
            return value

        return clean_value(document)  # type: ignore[return-value]

    @staticmethod
    def sort_cursor(cursor, field: str = "generated_at"):
        """Apply stable newest-first ordering while supporting lightweight test cursors."""
        sort = getattr(cursor, "sort", None)
        return sort([(field, -1), ("_id", -1)]) if callable(sort) else cursor
