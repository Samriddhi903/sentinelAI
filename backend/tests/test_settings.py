"""Tests for application settings."""

import os

from app.core.config import Settings, get_settings


def test_settings_defaults(monkeypatch) -> None:
    for key in (
        "MONGODB_DB_NAME",
        "LOG_FORMAT",
        "SECRET_KEY",
        "ALLOWED_ORIGINS",
        "MAX_UPLOAD_SIZE_MB",
    ):
        monkeypatch.delenv(key, raising=False)

    settings = Settings()

    assert settings.app_name == "SentinelAI"
    assert settings.mongodb_db_name == "sentinelai"
    assert settings.log_format == "console"
    assert settings.max_upload_size_mb == 10


def test_settings_load_from_environment(monkeypatch) -> None:
    monkeypatch.setenv("MONGODB_DB_NAME", "sentinel_test")
    monkeypatch.setenv("LOG_FORMAT", "json")
    monkeypatch.setenv("SECRET_KEY", "phase1-secret")

    settings = Settings()

    assert settings.mongodb_db_name == "sentinel_test"
    assert settings.log_format == "json"
    assert settings.secret_key == "phase1-secret"


def test_cors_origins_parsing(monkeypatch) -> None:
    monkeypatch.setenv(
        "ALLOWED_ORIGINS",
        "http://localhost:5173, http://localhost:3000",
    )

    settings = Settings()
    assert settings.cors_origins == ["http://localhost:5173", "http://localhost:3000"]


def test_get_settings_is_cached() -> None:
    os.environ.setdefault("SECRET_KEY", "cached-secret")
    first = get_settings()
    second = get_settings()
    assert first is second
