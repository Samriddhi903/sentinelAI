"""Application-specific exceptions with stable error codes."""

from fastapi import status


class AppError(Exception):
    """Base application error mapped to an HTTP response."""

    def __init__(
        self,
        detail: str,
        code: str,
        status_code: int = status.HTTP_400_BAD_REQUEST,
    ) -> None:
        self.detail = detail
        self.code = code
        self.status_code = status_code
        super().__init__(detail)


class DatabaseUnavailableError(AppError):
    def __init__(self) -> None:
        super().__init__(
            detail="Database unavailable — cannot accept uploads",
            code="DATABASE_UNAVAILABLE",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )


class UploadNotFoundError(AppError):
    def __init__(self, upload_id: str) -> None:
        super().__init__(
            detail=f"Upload not found: {upload_id}",
            code="UPLOAD_NOT_FOUND",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class InvalidExtensionError(AppError):
    def __init__(self, extension: str) -> None:
        super().__init__(
            detail=f"File extension not allowed: {extension}",
            code="INVALID_EXTENSION",
        )


class InvalidMimeError(AppError):
    def __init__(self, mime_type: str) -> None:
        super().__init__(
            detail=f"MIME type not allowed: {mime_type}",
            code="INVALID_MIME",
        )


class FileTooLargeError(AppError):
    def __init__(self, max_size_mb: int) -> None:
        super().__init__(
            detail=f"File exceeds maximum size of {max_size_mb} MB",
            code="FILE_TOO_LARGE",
        )


class EmptyFileError(AppError):
    def __init__(self) -> None:
        super().__init__(
            detail="Uploaded file is empty",
            code="EMPTY_FILE",
        )


class InvalidFilenameError(AppError):
    def __init__(self, reason: str) -> None:
        super().__init__(
            detail=f"Invalid filename: {reason}",
            code="INVALID_FILENAME",
        )


class ZipBombError(AppError):
    def __init__(self) -> None:
        super().__init__(
            detail="Compressed file exceeds safe decompression limits",
            code="ZIP_BOMB_DETECTED",
        )


class FileStorageError(AppError):
    def __init__(self, reason: str) -> None:
        super().__init__(
            detail=f"Failed to store uploaded file: {reason}",
            code="FILE_STORAGE_ERROR",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
