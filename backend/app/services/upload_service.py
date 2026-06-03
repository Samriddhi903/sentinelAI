"""Upload orchestration service."""

from uuid import uuid4

from app.core.exceptions import DatabaseUnavailableError, FileStorageError, UploadNotFoundError
from app.core.logging import get_logger
from app.database.connection import DatabaseManager
from app.models.upload import UploadStatus
from app.repositories.upload_repository import UploadRepository
from app.schemas.upload import UploadCreateResponse, UploadStatusResponse
from app.services.file_storage_service import FileStorageService
from app.services.upload_validator import UploadValidator
from app.services.format_detection_service import FormatDetectionService
from datetime import datetime, UTC

logger = get_logger(__name__)


class UploadService:
    """Coordinates validation, storage, and upload metadata persistence."""

    def __init__(
        self,
        db_manager: DatabaseManager,
        upload_repository: UploadRepository,
        file_storage: FileStorageService,
        upload_validator: UploadValidator,
        format_detection_service: FormatDetectionService | None = None,
    ) -> None:
        self._db_manager = db_manager
        self._upload_repository = upload_repository
        self._file_storage = file_storage
        self._upload_validator = upload_validator
        self._format_detection_service = format_detection_service

    async def create_upload(
        self,
        filename: str | None,
        content: bytes,
    ) -> UploadCreateResponse:
        await self._require_database()

        original_name, extension = self._upload_validator.validate(filename, content)
        stored_filename = f"{uuid4()}{extension}"

        document = await self._upload_repository.create_pending(
            original_name=original_name,
            stored_filename=stored_filename,
            size_bytes=len(content),
        )
        upload_id = document["upload_id"]

        try:
            await self._file_storage.save_file(stored_filename, content)
            updated = await self._upload_repository.update_status(
                upload_id,
                UploadStatus.UPLOADED,
            )
        except FileStorageError:
            await self._upload_repository.update_status(upload_id, UploadStatus.FAILED)
            raise

        if updated is None:
            await self._file_storage.delete_file(stored_filename)
            raise FileStorageError("upload record missing after save")

        return UploadCreateResponse(
            upload_id=updated["upload_id"],
            original_name=updated["original_name"],
            filename=updated["filename"],
            status=updated["status"],
            size_bytes=updated["size_bytes"],
            uploaded_at=updated["uploaded_at"],
        )

    async def get_upload_status(self, upload_id: str) -> UploadStatusResponse:
        await self._require_database()

        document = await self._upload_repository.find_by_upload_id(upload_id)
        if document is None:
            raise UploadNotFoundError(upload_id)

        return UploadStatusResponse(
            upload_id=document["upload_id"],
            original_name=document["original_name"],
            filename=document["filename"],
            status=document["status"],
            format=document.get("format"),
            confidence=document.get("confidence"),
            size_bytes=document["size_bytes"],
            uploaded_at=document["uploaded_at"],
            processed_at=document.get("processed_at"),
        )

    async def process_upload(self, upload_id: str) -> UploadStatusResponse:
        await self._require_database()

        document = await self._upload_repository.find_by_upload_id(upload_id)
        if document is None:
            raise UploadNotFoundError(upload_id)

        # Only process uploads that have been uploaded
        if document["status"] != UploadStatus.UPLOADED.value:
            raise FileStorageError("upload not in uploaded state")

        # mark processing
        await self._upload_repository.update_status(upload_id, UploadStatus.PROCESSING)

        try:
            content = await self._file_storage.read_file(document["filename"])  # bytes
            text = content.decode("utf-8", errors="replace")

            if self._format_detection_service is None:
                detection = {"format": None, "confidence": 0.0, "alternatives": []}
            else:
                detection = self._format_detection_service.detect_format(text)

            processed_at = datetime.now(UTC)

            updated = await self._upload_repository.update_processing_result(
                upload_id,
                status=UploadStatus.PROCESSED,
                format=detection.get("format"),
                confidence=detection.get("confidence"),
                processed_at=processed_at,
            )
        except Exception:
            await self._upload_repository.update_status(upload_id, UploadStatus.FAILED)
            raise

        if updated is None:
            raise FileStorageError("upload record missing after processing")

        return UploadStatusResponse(
            upload_id=updated["upload_id"],
            original_name=updated["original_name"],
            filename=updated["filename"],
            status=updated["status"],
            format=updated.get("format"),
            confidence=updated.get("confidence"),
            size_bytes=updated["size_bytes"],
            uploaded_at=updated["uploaded_at"],
            processed_at=updated.get("processed_at"),
        )

    async def _require_database(self) -> None:
        if not await self._db_manager.ping():
            raise DatabaseUnavailableError()
