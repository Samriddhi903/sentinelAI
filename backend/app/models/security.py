from enum import StrEnum


class DetectionSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


DETECTIONS_COLLECTION = "detections"
RISK_ASSESSMENTS_COLLECTION = "risk_assessments"
INVESTIGATIONS_COLLECTION = "investigations"
