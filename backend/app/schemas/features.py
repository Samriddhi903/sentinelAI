from datetime import datetime

from pydantic import BaseModel


class FeatureResponse(BaseModel):
    feature_id: str
    upload_id: str
    source_ip: str
    request_count: int
    unique_paths: int
    status_2xx: int
    status_4xx: int
    status_5xx: int
    error_rate: float
    generated_at: datetime


class FeaturesExtractionResponse(BaseModel):
    upload_id: str
    status: str
    generated_at: datetime
