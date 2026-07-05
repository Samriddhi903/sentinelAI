"""Typed domain models shared by pipeline stages."""

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class NormalizedEvent(BaseModel):
    """Canonical event passed from parsers to feature engineering."""

    model_config = ConfigDict(extra="allow")

    event_id: str
    upload_id: str
    timestamp: datetime
    source: str
    event_type: str
    ip: str | None = None
    user: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_log_timestamp(cls, value: object) -> object:
        if not isinstance(value, str):
            return value
        for pattern in ("%d/%b/%Y:%H:%M:%S %z", "%b %d %H:%M:%S"):
            try:
                parsed = datetime.strptime(value, pattern)
                if pattern == "%b %d %H:%M:%S":
                    parsed = parsed.replace(year=datetime.now(UTC).year, tzinfo=UTC)
                return parsed
            except ValueError:
                continue
        return value


class FeatureDocument(BaseModel):
    """Extensible feature vector persisted for a source within an upload."""

    model_config = ConfigDict(extra="allow")

    feature_id: str
    upload_id: str
    source_ip: str
    generated_at: datetime
