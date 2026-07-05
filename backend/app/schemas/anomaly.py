from datetime import datetime
from pydantic import BaseModel


class AnomalyDetectionSchema(BaseModel):
    anomaly_id: str
    upload_id: str
    source_ip: str
    anomaly_score: int
    is_anomalous: bool
    generated_at: datetime

