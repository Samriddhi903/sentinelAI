from datetime import datetime
from typing import Any
from uuid import uuid4

from motor.motor_asyncio import AsyncIOMotorDatabase
from pymongo import ReturnDocument

from app.database.base_repository import BaseRepository


EVENTS_COLLECTION = "events"


class EventRepository(BaseRepository):
    def __init__(self, database: AsyncIOMotorDatabase) -> None:
        super().__init__(database, EVENTS_COLLECTION)

    async def ensure_indexes(self) -> None:
        await self.collection.create_index("event_id", unique=True)
        await self.collection.create_index("upload_id")
        await self.collection.create_index("timestamp")
        await self.collection.create_index("event_type")

    async def insert_events(self, events: list[dict[str, Any]]) -> None:
        if not events:
            return None
        # ensure each event has an event_id
        for e in events:
            e.setdefault("event_id", str(uuid4()))
            if "timestamp" not in e:
                e["timestamp"] = datetime.utcnow()
        await self.collection.insert_many(events)

    async def find_by_upload_id(self, upload_id: str) -> list[dict[str, Any]]:
        cursor = self.collection.find({"upload_id": upload_id})
        return [doc async for doc in cursor]
