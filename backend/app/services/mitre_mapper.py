from app.models.security_catalog import get_rule_metadata
from app.services.detection_engine import Detection


class MitreMapper:
    def map_detection(self, detection: Detection) -> list[str]:
        metadata = get_rule_metadata(detection.detection_type)
        return list(metadata.mitre_techniques) if metadata else []

    def map_detections(self, detections: list[Detection]) -> list[str]:
        technique_ids: list[str] = []
        for detection in detections:
            for technique in self.map_detection(detection):
                if technique not in technique_ids:
                    technique_ids.append(technique)
        return technique_ids
