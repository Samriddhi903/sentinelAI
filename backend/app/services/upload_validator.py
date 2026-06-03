"""File upload validation: extension, MIME, size, and compression safety."""

import gzip
import io
import re
from pathlib import PurePath

import magic

from app.core.config import Settings
from app.core.exceptions import (
    EmptyFileError,
    FileTooLargeError,
    InvalidExtensionError,
    InvalidFilenameError,
    InvalidMimeError,
    ZipBombError,
)
from app.models.upload import (
    ALLOWED_EXTENSIONS,
    BLOCKED_MIME_PREFIXES,
    EXTENSION_MIME_MAP,
    MAX_GZIP_COMPRESSION_RATIO,
    MAX_GZIP_UNCOMPRESSED_MULTIPLIER,
)

UNSAFE_FILENAME_PATTERN = re.compile(r"[^\w.\- ]")
RESERVED_WINDOWS_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
}


class UploadValidator:
    """Validates uploaded files before persistence."""

    def __init__(self, settings: Settings) -> None:
        self._max_bytes = settings.max_upload_size_mb * 1024 * 1024
        self._max_gzip_uncompressed = self._max_bytes * MAX_GZIP_UNCOMPRESSED_MULTIPLIER

    def validate(self, filename: str | None, content: bytes) -> tuple[str, str]:
        if not filename or not filename.strip():
            raise InvalidFilenameError("filename is required")

        sanitized_name = self._sanitize_filename(filename)

        if not content:
            raise EmptyFileError()

        if len(content) > self._max_bytes:
            raise FileTooLargeError(self._max_size_mb())

        extension = self._extract_extension(sanitized_name)
        mime_type = magic.from_buffer(content, mime=True)

        self._validate_mime(extension, mime_type)

        if extension == ".gz":
            self._validate_gzip_safe(content)

        return sanitized_name, extension

    def _max_size_mb(self) -> int:
        return self._max_bytes // (1024 * 1024)

    def _sanitize_filename(self, filename: str) -> str:
        if ".." in filename or "/" in filename or "\\" in filename:
            raise InvalidFilenameError("path traversal detected")

        normalized = filename.strip()
        if not normalized or normalized in {".", ".."}:
            raise InvalidFilenameError("path traversal detected")

        if UNSAFE_FILENAME_PATTERN.search(normalized):
            raise InvalidFilenameError("contains unsafe characters")

        stem = PurePath(normalized).stem.upper()
        if stem in RESERVED_WINDOWS_NAMES:
            raise InvalidFilenameError("reserved filename")

        return normalized

    def _extract_extension(self, filename: str) -> str:
        extension = PurePath(filename).suffix.lower()
        if extension not in ALLOWED_EXTENSIONS:
            raise InvalidExtensionError(extension or "<none>")
        return extension

    def _validate_mime(self, extension: str, mime_type: str) -> None:
        if not mime_type:
            raise InvalidMimeError("unknown")

        lowered = mime_type.lower()
        for blocked in BLOCKED_MIME_PREFIXES:
            if lowered.startswith(blocked):
                raise InvalidMimeError(mime_type)

        allowed = EXTENSION_MIME_MAP.get(extension, set())
        if lowered not in allowed:
            raise InvalidMimeError(mime_type)

    def _validate_gzip_safe(self, content: bytes) -> None:
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(content)) as gzip_file:
                uncompressed_size = 0
                while chunk := gzip_file.read(8192):
                    uncompressed_size += len(chunk)
                    if uncompressed_size > self._max_gzip_uncompressed:
                        raise ZipBombError()

                    ratio = uncompressed_size / max(len(content), 1)
                    if ratio > MAX_GZIP_COMPRESSION_RATIO:
                        raise ZipBombError()
        except gzip.BadGzipFile as exc:
            raise InvalidMimeError("invalid gzip content") from exc
