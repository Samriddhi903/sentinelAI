from datetime import datetime
from typing import Any
from uuid import uuid4

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.database.base_repository import BaseRepository
from app.models.security import REPORTS_COLLECTION


class ReportRepository(BaseRepository):
    def __init__(self, database: AsyncIOMotorDatabase) -> None:
        super().__init__(database, REPORTS_COLLECTION)

    async def ensure_indexes(self) -> None:
        await self.collection.create_index("report_id", unique=True)
        await self.collection.create_index("upload_id")
        await self.collection.create_index("severity")
        await self.collection.create_index("risk_score")
        await self.collection.create_index("generated_at")

    async def upsert_report(self, report: dict[str, Any]) -> dict[str, Any]:
        report.setdefault("report_id", str(uuid4()))
        report.setdefault("generated_at", datetime.utcnow())
        await self.collection.replace_one(
            {"upload_id": report["upload_id"]},
            report,
            upsert=True,
        )
        return report

    async def find_by_upload_id(self, upload_id: str) -> dict[str, Any] | None:
        document = await self.collection.find_one({"upload_id": upload_id})
        if document is None:
            return None
        return self.sanitize_document(document)
