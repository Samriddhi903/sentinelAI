"""In-memory upload repository for tests."""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.models.upload import UploadStatus


class InMemoryUploadRepository:
    """Test double that mirrors UploadRepository behavior without MongoDB."""

    def __init__(self) -> None:
        self.documents: dict[str, dict[str, Any]] = {}

    async def ensure_indexes(self) -> None:
        return None

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
        self.documents[upload_id] = document
        return document

    async def update_status(self, upload_id: str, status: UploadStatus) -> dict[str, Any] | None:
        document = self.documents.get(upload_id)
        if document is None:
            return None
        document = {**document, "status": status.value}
        self.documents[upload_id] = document
        return document

    async def update_processing_result(
        self,
        upload_id: str,
        *,
        status: UploadStatus,
        format: str | None,
        confidence: float | None,
        processed_at,
    ) -> dict[str, Any] | None:
        document = self.documents.get(upload_id)
        if document is None:
            return None
        document = {
            **document,
            "status": status.value,
            "format": format,
            "confidence": confidence,
            "processed_at": processed_at,
        }
        self.documents[upload_id] = document
        return document

    async def find_by_upload_id(self, upload_id: str) -> dict[str, Any] | None:
        return self.documents.get(upload_id)

    async def delete_by_upload_id(self, upload_id: str) -> None:
        self.documents.pop(upload_id, None)

    async def update_normalization_result(self, upload_id: str, *, status: UploadStatus, normalized_at) -> dict[str, Any] | None:
        document = self.documents.get(upload_id)
        if document is None:
            return None
        document = {**document, "status": status.value, "normalized_at": normalized_at}
        self.documents[upload_id] = document
        return document

    async def update_feature_extraction_result(self, upload_id: str, *, status: UploadStatus, generated_at) -> dict[str, Any] | None:
        document = self.documents.get(upload_id)
        if document is None:
            return None
        document = {**document, "status": status.value, "features_generated_at": generated_at}
        self.documents[upload_id] = document
        return document

    async def update_analysis_result(self, upload_id: str, *, status: UploadStatus, analyzed_at) -> dict[str, Any] | None:
        document = self.documents.get(upload_id)
        if document is None:
            return None
        document = {**document, "status": status.value, "analysis_generated_at": analyzed_at}
        self.documents[upload_id] = document
        return document
