"""Application configuration loaded from environment variables."""

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Centralized application settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "SentinelAI"
    app_version: str = "0.1.0"
    debug: bool = False

    mongodb_uri: str = Field(default="", alias="MONGODB_URI")
    mongodb_db_name: str = Field(default="sentinelai", alias="MONGODB_DB_NAME")
    secret_key: str = Field(default="", alias="SECRET_KEY")

    log_format: Literal["console", "json"] = Field(
        default="console",
        alias="LOG_FORMAT",
    )
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    allowed_origins: str = Field(
        default="http://localhost:5173",
        alias="ALLOWED_ORIGINS",
    )
    upload_dir: str = Field(default="./uploads", alias="UPLOAD_DIR")
    max_upload_size_mb: int = Field(default=10, alias="MAX_UPLOAD_SIZE_MB")

    gemini_api_key: str = Field(default="", alias="GEMINI_API_KEY")

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.allowed_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    """Return cached settings instance."""
    return Settings()
