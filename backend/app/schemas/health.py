"""Health check response schemas."""

from pydantic import BaseModel, Field


class LivenessResponse(BaseModel):
    status: str = Field(examples=["alive"])
    version: str = Field(examples=["0.1.0"])


class ReadinessResponse(BaseModel):
    status: str = Field(examples=["ready", "not_ready"])
    mongodb: str = Field(examples=["connected", "disconnected"])
