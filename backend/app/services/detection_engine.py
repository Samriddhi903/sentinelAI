from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, List
from uuid import uuid4

from pydantic import BaseModel, Field

from app.models.security import DetectionSeverity


class Detection(BaseModel):
    detection_id: str = Field(default_factory=lambda: str(uuid4()))
    upload_id: str
    source_ip: str
    detection_type: str
    severity: DetectionSeverity
    confidence: float = Field(default=1.0)
    details: dict[str, Any] = Field(default_factory=dict)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True)
class DetectionRule:
    detection_type: str
    severity: DetectionSeverity
    condition: Callable[[dict[str, Any]], bool]
    description: str
    confidence: float = 1.0

    def evaluate(self, upload_id: str, source_ip: str, feature_document: dict[str, Any]) -> Detection | None:
        if self.condition(feature_document):
            return Detection(
                upload_id=upload_id,
                source_ip=source_ip,
                detection_type=self.detection_type,
                severity=self.severity,
                confidence=self.confidence,
                details={
                    "description": self.description,
                    "feature_document": {k: v for k, v in feature_document.items() if k != "generated_at"},
                },
            )
        return None


class DetectionEngine:
    def __init__(self, rules: List[DetectionRule] | None = None) -> None:
        self._rules = rules if rules is not None else self._default_rules()

    def _default_rules(self) -> List[DetectionRule]:
        return [
            DetectionRule(
                detection_type="sql_injection",
                severity=DetectionSeverity.HIGH,
                condition=lambda f: int(f.get("sqli_attempt_count", 0)) > 0,
                description="SQL injection activity detected.",
            ),
            DetectionRule(
                detection_type="xss",
                severity=DetectionSeverity.MEDIUM,
                condition=lambda f: int(f.get("xss_attempt_count", 0)) > 0,
                description="Cross site scripting activity detected.",
            ),
            DetectionRule(
                detection_type="directory_enumeration",
                severity=DetectionSeverity.MEDIUM,
                condition=lambda f: int(f.get("directory_enumeration_count", 0)) >= 3,
                description="Directory enumeration is present.",
            ),
            DetectionRule(
                detection_type="sensitive_file_discovery",
                severity=DetectionSeverity.HIGH,
                condition=lambda f: int(f.get("sensitive_file_probe_count", 0)) > 0,
                description="Sensitive file probe activity detected.",
            ),
            DetectionRule(
                detection_type="path_traversal",
                severity=DetectionSeverity.HIGH,
                condition=lambda f: int(f.get("path_traversal_count", 0)) > 0,
                description="Path traversal activity detected.",
            ),
            DetectionRule(
                detection_type="webshell_activity",
                severity=DetectionSeverity.CRITICAL,
                condition=lambda f: int(f.get("webshell_access_count", 0)) > 0,
                description="Webshell activity detected.",
            ),
            DetectionRule(
                detection_type="brute_force",
                severity=DetectionSeverity.MEDIUM,
                condition=lambda f: int(f.get("brute_force_attempt_count", 0)) >= 5
                or int(f.get("failed_login_count", 0)) >= 5,
                description="Brute force activity detected.",
            ),
            DetectionRule(
                detection_type="privilege_escalation",
                severity=DetectionSeverity.CRITICAL,
                condition=lambda f: int(f.get("sudo_event_count", 0)) > 0
                or int(f.get("privilege_escalation_count", 0)) > 0,
                description="Privilege escalation activity detected.",
            ),
            DetectionRule(
                detection_type="reconnaissance",
                severity=DetectionSeverity.LOW,
                condition=lambda f: int(f.get("reconnaissance_count", 0)) > 0,
                description="Reconnaissance activity detected.",
            ),
            DetectionRule(
                detection_type="suspicious_cron",
                severity=DetectionSeverity.HIGH,
                condition=lambda f: int(f.get("suspicious_cron_count", 0)) > 0,
                description="Suspicious cron activity detected.",
            ),
            DetectionRule(
                detection_type="critical_file_modification",
                severity=DetectionSeverity.CRITICAL,
                condition=lambda f: int(f.get("critical_file_modification_count", 0)) > 0,
                description="Critical file modification activity detected.",
            ),
            DetectionRule(
                detection_type="account_creation",
                severity=DetectionSeverity.HIGH,
                condition=lambda f: int(f.get("new_user_count", 0)) > 0,
                description="New user account creation detected.",
            ),
            DetectionRule(
                detection_type="credential_modification",
                severity=DetectionSeverity.HIGH,
                condition=lambda f: int(f.get("password_change_count", 0)) > 0,
                description="Credential or password modification detected.",
            ),
            DetectionRule(
                detection_type="firewall_evasion",
                severity=DetectionSeverity.MEDIUM,
                condition=lambda f: int(f.get("firewall_block_count", 0)) > 0,
                description="Firewall evasion or blocking activity detected.",
            ),
            DetectionRule(
                detection_type="command_execution",
                severity=DetectionSeverity.HIGH,
                condition=lambda f: int(f.get("command_execution_count", 0)) > 0,
                description="Command execution activity detected.",
            ),
            DetectionRule(
                detection_type="sensitive_file_access",
                severity=DetectionSeverity.HIGH,
                condition=lambda f: int(f.get("sensitive_file_access_count", 0)) > 0,
                description="Sensitive file access activity detected.",
            ),
        ]

    def detect(self, feature_documents: Iterable[dict[str, Any]]) -> List[Detection]:
        detections: list[Detection] = []
        for document in feature_documents:
            upload_id = document.get("upload_id", "unknown")
            source_ip = document.get("source_ip", "unknown")
            for rule in self._rules:
                detection = rule.evaluate(upload_id, source_ip, document)
                if detection is not None:
                    detections.append(detection)
        return detections
