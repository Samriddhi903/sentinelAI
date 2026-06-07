from typing import List

from app.services.detection_engine import Detection


class TimelineBuilder:
    _phase_map: dict[str, str] = {
        "sql_injection": "initial_access",
        "xss": "initial_access",
        "directory_enumeration": "reconnaissance",
        "sensitive_file_discovery": "discovery",
        "path_traversal": "execution",
        "webshell_activity": "persistence",
        "brute_force": "authentication_abuse",
        "privilege_escalation": "privilege_escalation",
        "reconnaissance": "reconnaissance",
        "suspicious_cron": "persistence",
        "critical_file_modification": "persistence",
    }

    def build_attack_chain(self, detections: List[Detection]) -> List[str]:
        attack_chain: list[str] = []
        for detection in detections:
            phase = self._phase_map.get(detection.detection_type)
            if phase is None:
                continue
            if not attack_chain or attack_chain[-1] != phase:
                attack_chain.append(phase)
        return attack_chain
