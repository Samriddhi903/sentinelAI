"""Local filesystem storage for uploaded log files."""

from pathlib import Path

import aiofiles

from app.core.config import Settings
from app.core.exceptions import FileStorageError
from app.core.logging import get_logger

logger = get_logger(__name__)


class FileStorageService:
    """Persists validated uploads to the configured local directory."""

    def __init__(self, settings: Settings) -> None:
        self._upload_dir = Path(settings.upload_dir).resolve()

    @property
    def upload_dir(self) -> Path:
        return self._upload_dir

    def ensure_upload_dir(self) -> None:
        self._upload_dir.mkdir(parents=True, exist_ok=True)

    async def save_file(self, stored_filename: str, content: bytes) -> Path:
        self.ensure_upload_dir()
        destination = self._upload_dir / stored_filename

        if destination.exists():
            raise FileStorageError("stored filename already exists")

        try:
            async with aiofiles.open(destination, mode="wb") as file_handle:
                await file_handle.write(content)
        except OSError as exc:
            logger.warning(
                "Failed to write uploaded file",
                extra={"filename": stored_filename, "error": str(exc)},
            )
            raise FileStorageError(str(exc)) from exc

        return destination

    async def delete_file(self, stored_filename: str) -> None:
        target = self._upload_dir / stored_filename
        if target.exists():
            target.unlink(missing_ok=True)
