"""Unit tests for upload validation rules."""

import gzip
import io
from unittest.mock import patch

import pytest

from app.core.config import Settings, get_settings
from app.core.exceptions import (
    EmptyFileError,
    FileTooLargeError,
    InvalidExtensionError,
    InvalidFilenameError,
    InvalidMimeError,
    ZipBombError,
)
from app.services.upload_validator import UploadValidator


@pytest.fixture
def validator(monkeypatch: pytest.MonkeyPatch) -> UploadValidator:
    monkeypatch.setenv("MAX_UPLOAD_SIZE_MB", "1")
    get_settings.cache_clear()
    return UploadValidator(Settings())


def test_validate_accepts_log_file(validator: UploadValidator) -> None:
    content = b"192.168.1.1 - - [03/Jun/2026:10:00:00 +0000] GET / HTTP/1.1 200"

    with patch("app.services.upload_validator.magic.from_buffer", return_value="text/plain"):
        original_name, extension = validator.validate("access.log", content)

    assert original_name == "access.log"
    assert extension == ".log"


def test_validate_rejects_disallowed_extension(validator: UploadValidator) -> None:
    with pytest.raises(InvalidExtensionError) as exc_info:
        validator.validate("malware.exe", b"content")

    assert exc_info.value.code == "INVALID_EXTENSION"


def test_validate_rejects_path_traversal(validator: UploadValidator) -> None:
    with pytest.raises(InvalidFilenameError) as exc_info:
        validator.validate("../../etc/passwd.log", b"content")

    assert exc_info.value.code == "INVALID_FILENAME"


def test_validate_rejects_empty_file(validator: UploadValidator) -> None:
    with pytest.raises(EmptyFileError):
        validator.validate("empty.log", b"")


def test_validate_rejects_oversized_file(validator: UploadValidator) -> None:
    oversized = b"a" * (1024 * 1024 + 1)

    with pytest.raises(FileTooLargeError) as exc_info:
        validator.validate("large.log", oversized)

    assert exc_info.value.code == "FILE_TOO_LARGE"


def test_validate_rejects_blocked_mime(validator: UploadValidator) -> None:
    with patch(
        "app.services.upload_validator.magic.from_buffer",
        return_value="application/x-msdownload",
    ):
        with pytest.raises(InvalidMimeError) as exc_info:
            validator.validate("payload.log", b"MZ")

    assert exc_info.value.code == "INVALID_MIME"


def test_validate_rejects_mime_extension_mismatch(validator: UploadValidator) -> None:
    with patch(
        "app.services.upload_validator.magic.from_buffer",
        return_value="application/json",
    ):
        with pytest.raises(InvalidMimeError):
            validator.validate("notes.log", b"plain text")


def test_validate_accepts_json_file(validator: UploadValidator) -> None:
    content = b'{"event_type": "failed_login"}'

    with patch(
        "app.services.upload_validator.magic.from_buffer",
        return_value="application/json",
    ):
        original_name, extension = validator.validate("events.json", content)

    assert original_name == "events.json"
    assert extension == ".json"


def test_validate_accepts_gzip_file(validator: UploadValidator) -> None:
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb") as gzip_file:
        gzip_file.write(b"line one\nline two\n")
    content = buffer.getvalue()

    with patch(
        "app.services.upload_validator.magic.from_buffer",
        return_value="application/gzip",
    ):
        original_name, extension = validator.validate("logs.gz", content)

    assert extension == ".gz"


def test_validate_rejects_gzip_bomb(validator: UploadValidator) -> None:
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb") as gzip_file:
        gzip_file.write(b"x" * (1024 * 1024 * 11))
    content = buffer.getvalue()

    with patch(
        "app.services.upload_validator.magic.from_buffer",
        return_value="application/gzip",
    ):
        with pytest.raises(ZipBombError) as exc_info:
            validator.validate("bomb.gz", content)

    assert exc_info.value.code == "ZIP_BOMB_DETECTED"
