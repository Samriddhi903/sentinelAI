"""Upload API request and response schemas."""

from datetime import datetime

from pydantic import BaseModel, Field


class UploadCreateResponse(BaseModel):
    upload_id: str
    original_name: str
    filename: str
    status: str
    size_bytes: int
    uploaded_at: datetime


class UploadStatusResponse(BaseModel):
    upload_id: str
    original_name: str
    filename: str
    status: str
    format: str | None = None
    confidence: float | None = None
    size_bytes: int
    uploaded_at: datetime
    processed_at: datetime | None = None


class ErrorResponse(BaseModel):
    detail: str
    code: str = Field(examples=["INVALID_EXTENSION"])
