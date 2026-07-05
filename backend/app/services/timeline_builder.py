from app.models.security_catalog import get_rule_metadata
from app.services.detection_engine import Detection


class TimelineBuilder:
    def build_attack_chain(self, detections: list[Detection]) -> list[str]:
        phases: dict[str, int] = {}
        for detection in detections:
            metadata = get_rule_metadata(detection.detection_type)
            if metadata is None:
                continue
            phases[metadata.timeline_phase] = metadata.timeline_order
        return [phase for phase, _ in sorted(phases.items(), key=lambda item: (item[1], item[0]))]
