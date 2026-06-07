from datetime import datetime
from typing import Any
from uuid import uuid4

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.database.base_repository import BaseRepository


FEATURES_COLLECTION = "features"


class FeatureRepository(BaseRepository):
    def __init__(self, database: AsyncIOMotorDatabase) -> None:
        super().__init__(database, FEATURES_COLLECTION)

    async def ensure_indexes(self) -> None:
        await self.collection.create_index("feature_id", unique=True)
        await self.collection.create_index("upload_id")
        await self.collection.create_index("source_ip")
        await self.collection.create_index("generated_at")

    async def insert_features(self, features: list[dict[str, Any]]) -> None:
        if not features:
            return None
        for f in features:
            f.setdefault("feature_id", str(uuid4()))
            f.setdefault("generated_at", datetime.utcnow())
        await self.collection.insert_many(features)

    async def find_by_upload_id(self, upload_id: str) -> list[dict[str, Any]]:
        cursor = self.collection.find({"upload_id": upload_id})
        return [doc async for doc in cursor]
