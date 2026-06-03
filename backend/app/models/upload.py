"""Upload document constants and status definitions."""

from enum import StrEnum


class UploadStatus(StrEnum):
    PENDING = "pending"
    UPLOADED = "uploaded"
    PROCESSING = "processing"
    PROCESSED = "processed"
    FAILED = "failed"


UPLOADS_COLLECTION = "uploads"

ALLOWED_EXTENSIONS = {".log", ".txt", ".json", ".gz"}

EXTENSION_MIME_MAP: dict[str, set[str]] = {
    ".log": {"text/plain", "application/octet-stream"},
    ".txt": {"text/plain", "application/octet-stream"},
    ".json": {"application/json", "text/plain", "application/octet-stream"},
    ".gz": {"application/gzip", "application/x-gzip", "application/octet-stream"},
}

BLOCKED_MIME_PREFIXES = (
    "application/x-executable",
    "application/x-msdownload",
    "application/x-dosexec",
    "application/javascript",
    "text/javascript",
    "application/x-sh",
    "text/x-python",
    "application/x-python",
    "application/zip",
    "application/x-zip-compressed",
)

MAX_GZIP_COMPRESSION_RATIO = 100
MAX_GZIP_UNCOMPRESSED_MULTIPLIER = 10
