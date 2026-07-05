from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.core.exceptions import FileStorageError, UploadNotFoundError
from app.models.pipeline import NormalizedEvent
from app.models.upload import UploadStatus
from app.parsers.registry import ParserRegistry
from app.repositories.event_repository import EventRepository
from app.repositories.upload_repository import UploadRepository
from app.services.file_storage_service import FileStorageService


class EventNormalizationService:
    def __init__(
        self,
        upload_repository: UploadRepository,
        event_repository: EventRepository,
        file_storage: FileStorageService,
        parser_registry: ParserRegistry,
    ) -> None:
        self._upload_repository = upload_repository
        self._event_repository = event_repository
        self._file_storage = file_storage
        self._parser_registry = parser_registry

    async def normalize_upload(self, upload_id: str) -> dict[str, Any]:
        document = await self._upload_repository.find_by_upload_id(upload_id)
        if document is None:
            raise UploadNotFoundError(upload_id)

        if document["status"] != "processed":
            raise FileStorageError("upload must be in processed state to normalize")

        claimed = await self._upload_repository.transition_status(
            upload_id,
            expected={UploadStatus.PROCESSED},
            target=UploadStatus.NORMALIZING,
        )
        if claimed is None:
            raise FileStorageError("upload must be in processed state to normalize")

        try:
            content = await self._file_storage.read_file(document["filename"])  # bytes
            text = content.decode("utf-8", errors="replace")

            # choose parser by stored format if available, else detect
            parser_name = document.get("format")
            parser = None
            if parser_name:
                parser = self._parser_registry.get_parser(parser_name)
            if parser is None:
                # detect best parser
                name, _, _ = self._parser_registry.detect_parser(text)
                parser = self._parser_registry.get_parser(name) if name else None

            normalized_events: list[dict[str, Any]] = []
            if parser:
                parsed = parser.parse(text)
                normalized = parser.normalize(parsed)
                for e in normalized:
                    e["event_id"] = str(uuid4())
                    e["upload_id"] = upload_id
                    # fill missing top-level fields
                    e.setdefault("timestamp", datetime.now(UTC))
                    e.setdefault("source", parser.name)
                    e.setdefault("ip", None)
                    e.setdefault("user", None)
                    e.setdefault("metadata", {})
                normalized_events = normalized
            else:
                # no parser found, produce a single raw event
                normalized_events = [
                    {
                        "event_id": str(uuid4()),
                        "upload_id": upload_id,
                        "timestamp": datetime.now(UTC),
                        "source": "raw",
                        "ip": None,
                        "user": None,
                        "event_type": "raw",
                        "metadata": {"raw": text},
                    }
                ]

            typed_events = [NormalizedEvent.model_validate(event) for event in normalized_events]
            await self._event_repository.insert_events(
                [event.model_dump() for event in typed_events]
            )

            normalized_at = datetime.now(UTC)
            updated = await self._upload_repository.update_normalization_result(
                upload_id, status=UploadStatus.NORMALIZED, normalized_at=normalized_at
            )
        except Exception:
            await self._upload_repository.transition_status(
                upload_id,
                expected={UploadStatus.NORMALIZING},
                target=UploadStatus.FAILED,
            )
            raise

        if updated is None:
            raise FileStorageError("upload record missing after normalization")

        return {
            "upload_id": updated["upload_id"],
            "status": updated["status"],
            "normalized_at": updated.get("normalized_at"),
        }
