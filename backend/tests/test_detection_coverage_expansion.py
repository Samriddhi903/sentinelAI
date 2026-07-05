"""Tests for expanded detection coverage and incident classification."""

import pytest

from app.models.security import DetectionSeverity
from app.services.detection_engine import Detection, DetectionEngine, DetectionRule
from app.services.incident_classifier import IncidentClassifier
from app.services.mitre_mapper import MitreMapper


class TestPrivilegeEscalationDetection:
    """Tests for privilege escalation detection via sudo events."""

    def test_no_privilege_escalation_on_benign_sudo(self):
        """Sudo alone (admin activity) should not trigger privilege escalation."""
        engine = DetectionEngine()
        feature = {
            "upload_id": "test-upload",
            "source_ip": "198.51.100.50",
            "sudo_event_count": 1,
            "brute_force_attempt_count": 0,
            "failed_login_count": 0,
            "successful_login_count": 0,
            "new_user_count": 0,
            "password_change_count": 0,
            "suspicious_cron_count": 0,
            "credential_modification_count": 0,
            "command_execution_count": 0,
            "privilege_escalation_count": 0,
        }

        detections = engine.detect([feature])

        assert not any(d.detection_type == "privilege_escalation" for d in detections)

    def test_no_detection_when_sudo_count_zero(self):
        """Test that sudo_event_count == 0 does not trigger detection."""
        engine = DetectionEngine()
        feature = {
            "upload_id": "test-upload",
            "source_ip": "198.51.100.50",
            "sudo_event_count": 0,
            "privilege_escalation_count": 0,
        }

        detections = engine.detect([feature])

        assert not any(d.detection_type == "privilege_escalation" for d in detections)


class TestAccountCreationDetection:
    """Tests for account creation detection via new_user_count."""

    def test_detect_new_user_count_greater_than_zero(self):
        """Test that new_user_count > 0 triggers account_creation detection."""
        engine = DetectionEngine()
        feature = {
            "upload_id": "test-upload",
            "source_ip": "198.51.100.50",
            "new_user_count": 1,
        }

        detections = engine.detect([feature])

        assert len(detections) > 0
        assert any(d.detection_type == "account_creation" for d in detections)
        acc_creation = next(d for d in detections if d.detection_type == "account_creation")
        assert acc_creation.severity == DetectionSeverity.HIGH
        assert acc_creation.confidence == 1.0

    def test_no_detection_when_new_user_count_zero(self):
        """Test that new_user_count == 0 does not trigger detection."""
        engine = DetectionEngine()
        feature = {
            "upload_id": "test-upload",
            "source_ip": "198.51.100.50",
            "new_user_count": 0,
        }

        detections = engine.detect([feature])

        assert not any(d.detection_type == "account_creation" for d in detections)


class TestCredentialModificationDetection:
    """Tests for credential modification detection via password_change_count."""

    def test_detect_password_change_count_greater_than_zero(self):
        """Test that password_change_count > 0 triggers credential_modification detection."""
        engine = DetectionEngine()
        feature = {
            "upload_id": "test-upload",
            "source_ip": "198.51.100.50",
            "password_change_count": 1,
        }

        detections = engine.detect([feature])

        assert len(detections) > 0
        assert any(d.detection_type == "credential_modification" for d in detections)
        cred_mod = next(d for d in detections if d.detection_type == "credential_modification")
        assert cred_mod.severity == DetectionSeverity.HIGH
        assert cred_mod.confidence == 1.0

    def test_no_detection_when_password_change_count_zero(self):
        """Test that password_change_count == 0 does not trigger detection."""
        engine = DetectionEngine()
        feature = {
            "upload_id": "test-upload",
            "source_ip": "198.51.100.50",
            "password_change_count": 0,
        }

        detections = engine.detect([feature])

        assert not any(d.detection_type == "credential_modification" for d in detections)


class TestCommandExecutionDetection:
    """Tests for command execution detection via command_execution_count."""

    def test_detect_command_execution_count_greater_than_zero(self):
        """Test that command_execution_count > 0 triggers command_execution detection."""
        engine = DetectionEngine()
        feature = {
            "upload_id": "test-upload",
            "source_ip": "198.51.100.50",
            "command_execution_count": 1,
        }

        detections = engine.detect([feature])

        assert len(detections) > 0
        assert any(d.detection_type == "command_execution" for d in detections)
        cmd_exec = next(d for d in detections if d.detection_type == "command_execution")
        assert cmd_exec.severity == DetectionSeverity.HIGH
        assert cmd_exec.confidence == 1.0

    def test_no_detection_when_command_execution_count_zero(self):
        """Test that command_execution_count == 0 does not trigger detection."""
        engine = DetectionEngine()
        feature = {
            "upload_id": "test-upload",
            "source_ip": "198.51.100.50",
            "command_execution_count": 0,
        }

        detections = engine.detect([feature])

        assert not any(d.detection_type == "command_execution" for d in detections)


class TestSensitiveFileAccessDetection:
    """Tests for sensitive file access detection via sensitive_file_access_count."""

    def test_detect_sensitive_file_access_count_greater_than_zero(self):
        """Test that sensitive_file_access_count > 0 triggers sensitive_file_access detection."""
        engine = DetectionEngine()
        feature = {
            "upload_id": "test-upload",
            "source_ip": "198.51.100.50",
            "sensitive_file_access_count": 1,
        }

        detections = engine.detect([feature])

        assert len(detections) > 0
        assert any(d.detection_type == "sensitive_file_access" for d in detections)
        file_access = next(d for d in detections if d.detection_type == "sensitive_file_access")
        assert file_access.severity == DetectionSeverity.HIGH
        assert file_access.confidence == 1.0

    def test_no_detection_when_sensitive_file_access_count_zero(self):
        """Test that sensitive_file_access_count == 0 does not trigger detection."""
        engine = DetectionEngine()
        feature = {
            "upload_id": "test-upload",
            "source_ip": "198.51.100.50",
            "sensitive_file_access_count": 0,
        }

        detections = engine.detect([feature])

        assert not any(d.detection_type == "sensitive_file_access" for d in detections)


class TestFirewallEvasionDetection:
    """Tests for firewall evasion detection via firewall_block_count."""

    def test_detect_firewall_block_count_greater_than_zero(self):
        """Test that firewall_block_count > 0 triggers firewall_evasion detection."""
        engine = DetectionEngine()
        feature = {
            "upload_id": "test-upload",
            "source_ip": "198.51.100.50",
            "firewall_block_count": 1,
        }

        detections = engine.detect([feature])

        assert len(detections) > 0
        assert any(d.detection_type == "firewall_evasion" for d in detections)
        firewall_evade = next(d for d in detections if d.detection_type == "firewall_evasion")
        assert firewall_evade.severity == DetectionSeverity.MEDIUM
        assert firewall_evade.confidence == 1.0

    def test_no_detection_when_firewall_block_count_zero(self):
        """Test that firewall_block_count == 0 does not trigger detection."""
        engine = DetectionEngine()
        feature = {
            "upload_id": "test-upload",
            "source_ip": "198.51.100.50",
            "firewall_block_count": 0,
        }

        detections = engine.detect([feature])

        assert not any(d.detection_type == "firewall_evasion" for d in detections)


class TestMitreMapping:
    """Tests for MITRE ATT&CK mappings of new detection types."""

    def test_privilege_escalation_maps_to_t1068(self):
        """Test that privilege_escalation maps to T1068."""
        mapper = MitreMapper()
        detection = Detection(
            detection_id="test",
            upload_id="test",
            source_ip="10.0.0.1",
            detection_type="privilege_escalation",
            severity=DetectionSeverity.CRITICAL,
        )

        techniques = mapper.map_detection(detection)
        assert "T1068" in techniques

    def test_account_creation_maps_to_t1136(self):
        """Test that account_creation maps to T1136."""
        mapper = MitreMapper()
        detection = Detection(
            detection_id="test",
            upload_id="test",
            source_ip="10.0.0.1",
            detection_type="account_creation",
            severity=DetectionSeverity.HIGH,
        )

        techniques = mapper.map_detection(detection)
        assert "T1136" in techniques

    def test_credential_modification_maps_to_t1098(self):
        """Test that credential_modification maps to T1098."""
        mapper = MitreMapper()
        detection = Detection(
            detection_id="test",
            upload_id="test",
            source_ip="10.0.0.1",
            detection_type="credential_modification",
            severity=DetectionSeverity.HIGH,
        )

        techniques = mapper.map_detection(detection)
        assert "T1098" in techniques

    def test_firewall_evasion_maps_to_t1562(self):
        """Test that firewall_evasion maps to T1562."""
        mapper = MitreMapper()
        detection = Detection(
            detection_id="test",
            upload_id="test",
            source_ip="10.0.0.1",
            detection_type="firewall_evasion",
            severity=DetectionSeverity.MEDIUM,
        )

        techniques = mapper.map_detection(detection)
        assert "T1562" in techniques

    def test_suspicious_cron_maps_to_t1053(self):
        """Test that suspicious_cron maps to T1053 (Scheduled Task/Job)."""
        mapper = MitreMapper()
        detection = Detection(
            detection_id="test",
            upload_id="test",
            source_ip="10.0.0.1",
            detection_type="suspicious_cron",
            severity=DetectionSeverity.HIGH,
        )

        techniques = mapper.map_detection(detection)
        assert "T1053" in techniques

    def test_command_execution_maps_to_t1059(self):
        """Test that command_execution maps to T1059."""
        mapper = MitreMapper()
        detection = Detection(
            detection_id="test",
            upload_id="test",
            source_ip="10.0.0.1",
            detection_type="command_execution",
            severity=DetectionSeverity.HIGH,
        )

        techniques = mapper.map_detection(detection)
        assert "T1059" in techniques

    def test_sensitive_file_access_maps_to_t1005(self):
        """Test that sensitive_file_access maps to T1005."""
        mapper = MitreMapper()
        detection = Detection(
            detection_id="test",
            upload_id="test",
            source_ip="10.0.0.1",
            detection_type="sensitive_file_access",
            severity=DetectionSeverity.HIGH,
        )

        techniques = mapper.map_detection(detection)
        assert "T1005" in techniques

    def test_path_traversal_maps_to_t1083(self):
        """Test that path_traversal maps to T1083."""
        mapper = MitreMapper()
        detection = Detection(
            detection_id="test",
            upload_id="test",
            source_ip="10.0.0.1",
            detection_type="path_traversal",
            severity=DetectionSeverity.HIGH,
        )

        techniques = mapper.map_detection(detection)
        assert "T1083" in techniques

    def test_sensitive_file_discovery_maps_to_t1083(self):
        """Test that sensitive_file_discovery maps to T1083."""
        mapper = MitreMapper()
        detection = Detection(
            detection_id="test",
            upload_id="test",
            source_ip="10.0.0.1",
            detection_type="sensitive_file_discovery",
            severity=DetectionSeverity.HIGH,
        )

        techniques = mapper.map_detection(detection)
        assert "T1083" in techniques


class TestIncidentClassification:
    """Tests for incident classification based on detection combinations."""

    def test_web_application_compromise_classification(self):
        """Test that SQL injection + webshell triggers Web Application Compromise."""
        detections = [
            Detection(
                detection_id="d1",
                upload_id="test",
                source_ip="10.0.0.1",
                detection_type="sql_injection",
                severity=DetectionSeverity.HIGH,
            ),
            Detection(
                detection_id="d2",
                upload_id="test",
                source_ip="10.0.0.1",
                detection_type="webshell_activity",
                severity=DetectionSeverity.CRITICAL,
            ),
        ]

        incident_type = IncidentClassifier.classify(detections)
        assert incident_type == "Web Application Compromise"

    def test_account_compromise_classification(self):
        """Test that brute force + privilege escalation triggers Account Compromise."""
        detections = [
            Detection(
                detection_id="d1",
                upload_id="test",
                source_ip="10.0.0.1",
                detection_type="brute_force",
                severity=DetectionSeverity.MEDIUM,
            ),
            Detection(
                detection_id="d2",
                upload_id="test",
                source_ip="10.0.0.1",
                detection_type="privilege_escalation",
                severity=DetectionSeverity.CRITICAL,
            ),
        ]

        incident_type = IncidentClassifier.classify(detections)
        assert incident_type == "Account Compromise"

    def test_persistence_establishment_classification(self):
        """Test that privilege escalation + account creation triggers Persistence Establishment."""
        detections = [
            Detection(
                detection_id="d1",
                upload_id="test",
                source_ip="10.0.0.1",
                detection_type="privilege_escalation",
                severity=DetectionSeverity.CRITICAL,
            ),
            Detection(
                detection_id="d2",
                upload_id="test",
                source_ip="10.0.0.1",
                detection_type="account_creation",
                severity=DetectionSeverity.HIGH,
            ),
        ]

        incident_type = IncidentClassifier.classify(detections)
        assert incident_type == "Persistence Establishment"

    def test_post_exploitation_activity_classification(self):
        """Test that command execution + sensitive file access triggers Post-Exploitation Activity."""
        detections = [
            Detection(
                detection_id="d1",
                upload_id="test",
                source_ip="10.0.0.1",
                detection_type="command_execution",
                severity=DetectionSeverity.HIGH,
            ),
            Detection(
                detection_id="d2",
                upload_id="test",
                source_ip="10.0.0.1",
                detection_type="sensitive_file_access",
                severity=DetectionSeverity.HIGH,
            ),
        ]

        incident_type = IncidentClassifier.classify(detections)
        assert incident_type == "Post-Exploitation Activity"

    def test_suspicious_activity_fallback_classification(self):
        """Test that unmatched single detection results in Suspicious Activity."""
        detections = [
            Detection(
                detection_id="d1",
                upload_id="test",
                source_ip="10.0.0.1",
                detection_type="reconnaissance",
                severity=DetectionSeverity.LOW,
            ),
        ]

        incident_type = IncidentClassifier.classify(detections)
        assert incident_type == "Suspicious Activity"

    def test_no_findings_on_empty_detections(self):
        """Test that empty detection list results in No Findings."""
        incident_type = IncidentClassifier.classify([])
        assert incident_type == "No Findings"

    def test_persistence_establishment_on_cred_mod_and_account_creation(self):
        """Test that credential modification + account creation triggers Persistence Establishment."""
        detections = [
            Detection(
                detection_id="d1",
                upload_id="test",
                source_ip="10.0.0.1",
                detection_type="credential_modification",
                severity=DetectionSeverity.HIGH,
            ),
            Detection(
                detection_id="d2",
                upload_id="test",
                source_ip="10.0.0.1",
                detection_type="account_creation",
                severity=DetectionSeverity.HIGH,
            ),
        ]

        incident_type = IncidentClassifier.classify(detections)
        assert incident_type == "Persistence Establishment"


class TestSyslogScenarioIntegration:
    """Integration tests for the syslog scenario from the requirements."""

    def test_syslog_scenario_generates_all_expected_detections(self):
        """Test that the syslog scenario generates all expected detections."""
        engine = DetectionEngine()
        feature = {
            "upload_id": "syslog-test",
            "source_ip": "198.51.100.100",
            "failed_login_count": 5,  # triggers brute_force
            "successful_login_count": 1,
            "sudo_event_count": 1,  # triggers privilege_escalation
            "new_user_count": 1,  # triggers account_creation
            "password_change_count": 1,  # triggers credential_modification
            "suspicious_cron_count": 1,  # triggers suspicious_cron
        }

        detections = engine.detect([feature])

        detection_types = {d.detection_type for d in detections}
        assert "brute_force" in detection_types
        assert "privilege_escalation" in detection_types
        assert "account_creation" in detection_types
        assert "credential_modification" in detection_types
        assert "suspicious_cron" in detection_types

    def test_syslog_scenario_generates_persistence_establishment_incident(self):
        """Test that multiple detections result in Persistence Establishment classification."""
        detections = [
            Detection(
                detection_id="d1",
                upload_id="syslog-test",
                source_ip="198.51.100.100",
                detection_type="privilege_escalation",
                severity=DetectionSeverity.CRITICAL,
            ),
            Detection(
                detection_id="d2",
                upload_id="syslog-test",
                source_ip="198.51.100.100",
                detection_type="account_creation",
                severity=DetectionSeverity.HIGH,
            ),
            Detection(
                detection_id="d3",
                upload_id="syslog-test",
                source_ip="198.51.100.100",
                detection_type="credential_modification",
                severity=DetectionSeverity.HIGH,
            ),
        ]

        incident_type = IncidentClassifier.classify(detections)
        assert incident_type == "Persistence Establishment"

    def test_all_syslog_detections_have_mitre_mappings(self):
        """Test that all generated syslog detections have valid MITRE mappings."""
        engine = DetectionEngine()
        mapper = MitreMapper()

        feature = {
            "upload_id": "syslog-test",
            "source_ip": "198.51.100.100",
            "failed_login_count": 5,
            "sudo_event_count": 1,
            "new_user_count": 1,
            "password_change_count": 1,
            "suspicious_cron_count": 1,
        }

        detections = engine.detect([feature])
        all_techniques = mapper.map_detections(detections)

        # Verify we have techniques for all detections
        assert len(all_techniques) > 0
        for detection in detections:
            techniques = mapper.map_detection(detection)
            assert len(techniques) > 0, f"No MITRE mapping for {detection.detection_type}"
