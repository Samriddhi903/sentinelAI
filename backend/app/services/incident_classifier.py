"""Incident classification based on detection combinations."""

from typing import Iterable

from app.services.detection_engine import Detection


class IncidentClassifier:
    """Classify incidents by combining multiple detections into attack scenarios."""

    @staticmethod
    def classify(detections: Iterable[Detection]) -> str:
        """Classify an incident based on detected attack patterns.

        Args:
            detections: Iterable of Detection objects

        Returns:
            incident_type: human-readable incident classification
        """
        detection_types = {d.detection_type for d in detections}

        # Rule 1: Web Application Compromise
        if "sql_injection" in detection_types and "webshell_activity" in detection_types:
            return "Web Application Compromise"

        # Rule 2: Account Compromise
        if "brute_force" in detection_types and "privilege_escalation" in detection_types:
            return "Account Compromise"

        # Rule 3: Persistence Establishment
        if "privilege_escalation" in detection_types and "account_creation" in detection_types:
            return "Persistence Establishment"

        # Rule 4: Post-Exploitation Activity
        if "command_execution" in detection_types and "sensitive_file_access" in detection_types:
            return "Post-Exploitation Activity"

        # Specific high-confidence scenarios
        if "credential_modification" in detection_types and "account_creation" in detection_types:
            return "Persistence Establishment"

        if (
            "privilege_escalation" in detection_types
            and ("credential_modification" in detection_types or "account_creation" in detection_types)
        ):
            return "Persistence Establishment"

        # Default fallback
        if detection_types:
            return "Suspicious Activity"

        return "No Findings"
