"""MongoDB repository for upload metadata."""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from motor.motor_asyncio import AsyncIOMotorDatabase

from pymongo import ReturnDocument

from app.database.base_repository import BaseRepository
from app.models.upload import UPLOADS_COLLECTION, UploadStatus


class UploadRepository(BaseRepository):
    """Persists and retrieves upload documents."""

    def __init__(self, database: AsyncIOMotorDatabase) -> None:
        super().__init__(database, UPLOADS_COLLECTION)

    async def ensure_indexes(self) -> None:
        await self.collection.create_index("upload_id", unique=True)
        await self.collection.create_index("uploaded_at")
        await self.collection.create_index("status")

    async def create_pending(
        self,
        *,
        original_name: str,
        stored_filename: str,
        size_bytes: int,
    ) -> dict[str, Any]:
        upload_id = str(uuid4())
        uploaded_at = datetime.now(UTC)

        document = {
            "upload_id": upload_id,
            "filename": stored_filename,
            "original_name": original_name,
            "status": UploadStatus.PENDING.value,
            "format": None,
            "confidence": None,
            "size_bytes": size_bytes,
            "uploaded_at": uploaded_at,
            "processed_at": None,
        }

        await self.collection.insert_one(document)
        return document

    async def update_status(self, upload_id: str, status: UploadStatus) -> dict[str, Any] | None:
        result = await self.collection.find_one_and_update(
            {"upload_id": upload_id},
            {"$set": {"status": status.value}},
            return_document=ReturnDocument.AFTER,
        )
        return result

    async def update_processing_result(
        self,
        upload_id: str,
        *,
        status: UploadStatus,
        format: str | None,
        confidence: float | None,
        processed_at,
    ) -> dict[str, Any] | None:
        update = {
            "$set": {
                "status": status.value,
                "format": format,
                "confidence": confidence,
                "processed_at": processed_at,
            }
        }
        result = await self.collection.find_one_and_update(
            {"upload_id": upload_id}, update, return_document=ReturnDocument.AFTER
        )
        return result

    async def update_normalization_result(
        self, upload_id: str, *, status: UploadStatus, normalized_at
    ) -> dict[str, Any] | None:
        update = {"$set": {"status": status.value, "normalized_at": normalized_at}}
        result = await self.collection.find_one_and_update(
            {"upload_id": upload_id}, update, return_document=ReturnDocument.AFTER
        )
        return result

    async def find_by_upload_id(self, upload_id: str) -> dict[str, Any] | None:
        return await self.collection.find_one({"upload_id": upload_id})

    async def delete_by_upload_id(self, upload_id: str) -> None:
        await self.collection.delete_one({"upload_id": upload_id})
