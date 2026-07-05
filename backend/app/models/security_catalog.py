"""Canonical security-intelligence metadata used across analysis services."""

from dataclasses import dataclass

from app.models.security import DetectionSeverity


@dataclass(frozen=True, slots=True)
class SecurityRuleMetadata:
    severity: DetectionSeverity
    risk_weight: int
    mitre_techniques: tuple[str, ...]
    timeline_phase: str
    timeline_order: int


SECURITY_RULE_CATALOG: dict[str, SecurityRuleMetadata] = {
    "reconnaissance": SecurityRuleMetadata(
        DetectionSeverity.LOW, 10, ("T1046",), "reconnaissance", 10
    ),
    "directory_enumeration": SecurityRuleMetadata(
        DetectionSeverity.MEDIUM, 15, ("T1595",), "reconnaissance", 10
    ),
    "sql_injection": SecurityRuleMetadata(
        DetectionSeverity.HIGH, 25, ("T1190",), "initial_access", 20
    ),
    "xss": SecurityRuleMetadata(DetectionSeverity.MEDIUM, 15, ("T1190",), "initial_access", 20),
    "brute_force": SecurityRuleMetadata(
        DetectionSeverity.MEDIUM, 20, ("T1110",), "authentication_abuse", 30
    ),
    "path_traversal": SecurityRuleMetadata(DetectionSeverity.HIGH, 30, ("T1083",), "execution", 40),
    "command_execution": SecurityRuleMetadata(
        DetectionSeverity.HIGH, 25, ("T1059",), "execution", 40
    ),
    "sensitive_file_discovery": SecurityRuleMetadata(
        DetectionSeverity.HIGH, 30, ("T1083",), "discovery", 50
    ),
    "sensitive_file_access": SecurityRuleMetadata(
        DetectionSeverity.HIGH, 30, ("T1005",), "discovery", 50
    ),
    "privilege_escalation": SecurityRuleMetadata(
        DetectionSeverity.CRITICAL, 50, ("T1068",), "privilege_escalation", 60
    ),
    "account_creation": SecurityRuleMetadata(
        DetectionSeverity.HIGH, 35, ("T1136",), "persistence", 70
    ),
    "credential_modification": SecurityRuleMetadata(
        DetectionSeverity.HIGH, 35, ("T1098",), "persistence", 70
    ),
    "webshell_activity": SecurityRuleMetadata(
        DetectionSeverity.CRITICAL, 60, ("T1505",), "persistence", 70
    ),
    "suspicious_cron": SecurityRuleMetadata(
        DetectionSeverity.HIGH, 40, ("T1053",), "persistence", 70
    ),
    "critical_file_modification": SecurityRuleMetadata(
        DetectionSeverity.CRITICAL, 50, ("T1098",), "persistence", 70
    ),
    "firewall_evasion": SecurityRuleMetadata(
        DetectionSeverity.MEDIUM, 15, ("T1562",), "defense_evasion", 80
    ),
}


def get_rule_metadata(detection_type: str) -> SecurityRuleMetadata | None:
    return SECURITY_RULE_CATALOG.get(detection_type)
