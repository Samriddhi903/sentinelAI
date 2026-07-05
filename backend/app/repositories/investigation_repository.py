from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.database.base_repository import BaseRepository
from app.models.security import INVESTIGATIONS_COLLECTION


class InvestigationRepository(BaseRepository):
    def __init__(self, database: AsyncIOMotorDatabase) -> None:
        super().__init__(database, INVESTIGATIONS_COLLECTION)

    async def ensure_indexes(self) -> None:
        await self.collection.create_index("investigation_id", unique=True)
        await self.collection.create_index("upload_id")
        await self.collection.create_index("source_ip")
        await self.collection.create_index("severity")
        await self.collection.create_index("risk_score")
        await self.collection.create_index("generated_at")

    async def insert_investigations(self, investigations: list[dict[str, Any]]) -> None:
        if not investigations:
            return None
        for investigation in investigations:
            investigation.setdefault("investigation_id", str(uuid4()))
            investigation.setdefault("generated_at", datetime.now(UTC))
            await self.collection.replace_one(
                {"upload_id": investigation["upload_id"]}, investigation, upsert=True
            )

    async def find_by_upload_id(self, upload_id: str) -> list[dict[str, Any]]:
        cursor = self.sort_cursor(self.collection.find({"upload_id": upload_id}))
        return [self.sanitize_document(doc) async for doc in cursor]
