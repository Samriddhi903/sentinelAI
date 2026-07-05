from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.database.base_repository import BaseRepository

ANOMALIES_COLLECTION = "anomalies"


class AnomalyRepository(BaseRepository):
    def __init__(self, database: AsyncIOMotorDatabase) -> None:
        super().__init__(database, ANOMALIES_COLLECTION)

    async def ensure_indexes(self) -> None:
        await self.collection.create_index("anomaly_id", unique=True)
        await self.collection.create_index("upload_id")
        await self.collection.create_index("source_ip")
        await self.collection.create_index("anomaly_score")
        await self.collection.create_index("is_anomalous")
        await self.collection.create_index("generated_at")

    async def insert_anomalies(self, anomalies: list[dict[str, Any]]) -> None:
        if not anomalies:
            return None

        for anomaly in anomalies:
            anomaly.setdefault("anomaly_id", str(uuid4()))
            anomaly.setdefault("generated_at", datetime.now(UTC))

        await self.collection.insert_many(anomalies)

    async def find_by_upload_id(self, upload_id: str) -> list[dict[str, Any]]:
        cursor = self.sort_cursor(self.collection.find({"upload_id": upload_id}))
        return [self.sanitize_document(doc) async for doc in cursor]

    async def find_latest_by_upload_id(self, upload_id: str) -> dict[str, Any] | None:
        doc = await self.collection.find_one({"upload_id": upload_id}, sort=[("generated_at", -1)])
        return self.sanitize_document(doc) if doc else None
