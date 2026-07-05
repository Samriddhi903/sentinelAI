from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.database.base_repository import BaseRepository
from app.models.security import RISK_ASSESSMENTS_COLLECTION


class RiskAssessmentRepository(BaseRepository):
    def __init__(self, database: AsyncIOMotorDatabase) -> None:
        super().__init__(database, RISK_ASSESSMENTS_COLLECTION)

    async def ensure_indexes(self) -> None:
        await self.collection.create_index("risk_id", unique=True)
        await self.collection.create_index("upload_id")
        await self.collection.create_index("source_ip")
        await self.collection.create_index("severity")
        await self.collection.create_index("risk_score")
        await self.collection.create_index("generated_at")

    async def insert_risk_assessments(self, assessments: list[dict[str, Any]]) -> None:
        if not assessments:
            return None
        for assessment in assessments:
            assessment.setdefault("risk_id", str(uuid4()))
            assessment.setdefault("generated_at", datetime.now(UTC))
            await self.collection.replace_one(
                {"upload_id": assessment["upload_id"]}, assessment, upsert=True
            )

    async def find_by_upload_id(self, upload_id: str) -> list[dict[str, Any]]:
        cursor = self.sort_cursor(self.collection.find({"upload_id": upload_id}))
        return [self.sanitize_document(doc) async for doc in cursor]
