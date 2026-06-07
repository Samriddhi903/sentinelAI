import pytest


def test_syslog_extractor_detects_sudo_from_process_field():
    from app.feature_extractors.syslog import SyslogFeatureExtractor

    extractor = SyslogFeatureExtractor()
    events = [
        {
            "event_type": "syslog_event",
            "ip": "198.51.100.100",
            "timestamp": "Jun 07 12:05:11",
            "metadata": {"message": "Accepted password for root from 198.51.100.100 port 55006 ssh2", "process": "sshd"},
        },
        {
            "event_type": "syslog_event",
            "ip": None,
            "timestamp": "Jun 07 12:06:01",
            "metadata": {
                "process": "sudo",
                "message": "attacker : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash",
            },
        },
    ]

    feats = extractor.extract(events)
    attacker = next(f for f in feats if f["source_ip"] == "198.51.100.100")

    assert attacker["sudo_event_count"] == 1


def test_syslog_extractor_from_sample():
    from app.feature_extractors.syslog import SyslogFeatureExtractor

    extractor = SyslogFeatureExtractor()
    events = [
        {"event_type": "syslog_event", "ip": "203.0.113.50", "metadata": {"message": "Failed password for root from 203.0.113.50"}},
        {"event_type": "syslog_event", "ip": "203.0.113.50", "metadata": {"message": "Failed password for root from 203.0.113.50"}},
        {"event_type": "syslog_event", "ip": "192.168.1.100", "metadata": {"message": "Accepted password for admin from 192.168.1.100"}},
    ]

    feats = extractor.extract(events)
    ips = {f["source_ip"] for f in feats}
    assert {"203.0.113.50", "192.168.1.100"} <= ips


def test_apache_extractor_counts():
    from app.feature_extractors.apache import ApacheFeatureExtractor

    ext = ApacheFeatureExtractor()
    events = [
        {"event_type": "http_request", "ip": "1.1.1.1", "metadata": {"path": "/admin", "status_code": "200"}, "raw": "GET /admin"},
        {"event_type": "http_request", "ip": "1.1.1.1", "metadata": {"path": "/admin", "status_code": "401"}, "raw": "POST /admin/login"},
        {"event_type": "http_request", "ip": "2.2.2.2", "metadata": {"path": "/etc/passwd", "status_code": "200"}, "raw": "GET /etc/passwd"},
    ]
    feats = ext.extract(events)
    assert any(f.get("sensitive_file_probe_count", 0) > 0 for f in feats)
