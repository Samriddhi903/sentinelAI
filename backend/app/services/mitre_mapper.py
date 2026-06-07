from typing import List

from app.services.detection_engine import Detection


class MitreMapper:
    _mapping: dict[str, List[str]] = {
        "sql_injection": ["T1190"],
        "brute_force": ["T1110"],
        "reconnaissance": ["T1046"],
        "privilege_escalation": ["T1068"],
        "critical_file_modification": ["T1098"],
        "webshell_activity": ["T1505"],
        "directory_enumeration": ["T1595"],
        "xss": ["T1190"],
        "path_traversal": ["T1083"],
        "sensitive_file_discovery": ["T1083"],
        "account_creation": ["T1136"],
        "credential_modification": ["T1098"],
        "command_execution": ["T1059"],
        "sensitive_file_access": ["T1005"],
        "firewall_evasion": ["T1562"],
        "suspicious_cron": ["T1053"],
    }

    def map_detection(self, detection: Detection) -> List[str]:
        return self._mapping.get(detection.detection_type, [])

    def map_detections(self, detections: List[Detection]) -> List[str]:
        technique_ids: list[str] = []
        for detection in detections:
            for technique in self.map_detection(detection):
                if technique not in technique_ids:
                    technique_ids.append(technique)
        return technique_ids
