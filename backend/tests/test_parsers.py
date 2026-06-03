import json
from pathlib import Path

from app.parsers.registry import ParserRegistry
from app.parsers.nginx_parser import NginxParser
from app.parsers.apache_parser import ApacheParser
from app.parsers.syslog_parser import SyslogParser
from app.parsers.json_log_parser import JsonLogParser
from app.services.format_detection_service import FormatDetectionService


def build_registry() -> ParserRegistry:
    registry = ParserRegistry()
    registry.register_parser(NginxParser())
    registry.register_parser(ApacheParser())
    registry.register_parser(SyslogParser())
    registry.register_parser(JsonLogParser())
    return registry


def test_parser_registry_detects_apache_access_log() -> None:
    registry = build_registry()
    sample = '192.168.1.1 - frank [03/Jun/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234'
    name, confidence, alternatives = registry.detect_parser(sample)

    assert name == "apache"
    assert confidence == 1.0
    assert all(isinstance(item, dict) for item in alternatives)


def test_parser_registry_detects_nginx_access_log() -> None:
    registry = build_registry()
    sample = '192.168.1.1 - frank [03/Jun/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "curl/7.68.0"'
    name, confidence, alternatives = registry.detect_parser(sample)

    assert name == "nginx"
    assert confidence == 1.0
    assert all(isinstance(item, dict) for item in alternatives)


def test_parser_registry_returns_unknown_for_ambiguous_common_log_format() -> None:
    registry = build_registry()
    sample = '192.168.1.1 - - [03/Jun/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/7.68.0" "extra"'
    name, confidence, alternatives = registry.detect_parser(sample)

    assert name in ("apache", "nginx")
    assert confidence == 0.9
    assert alternatives[0]["confidence"] == 0.9


def test_format_detection_service_returns_unknown_for_tied_scores() -> None:
    registry = build_registry()
    service = FormatDetectionService(registry)
    sample = '192.168.1.1 - - [03/Jun/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/7.68.0" "extra"'

    result = service.detect_format(sample)

    assert result["format"] == "unknown"
    assert result["confidence"] == 0.5
    assert isinstance(result["alternatives"], list)
    assert {alt["format"] for alt in result["alternatives"]} >= {"nginx", "apache"}


def test_json_log_parser_detects_single_json_object() -> None:
    parser = JsonLogParser()
    sample = '{"timestamp": "2026-06-03T10:30:00Z", "event_type": "login"}'

    assert parser.detect(sample) == 1.0
    assert parser.parse(sample) == [{"timestamp": "2026-06-03T10:30:00Z", "event_type": "login"}]


def test_json_log_parser_detects_json_array() -> None:
    parser = JsonLogParser()
    sample = '[{"timestamp": "2026-06-03T10:30:00Z", "event_type": "login"}, {"timestamp": "2026-06-03T10:31:00Z", "event_type": "logout"}]'

    assert parser.detect(sample) == 1.0
    assert parser.parse(sample) == [
        {"timestamp": "2026-06-03T10:30:00Z", "event_type": "login"},
        {"timestamp": "2026-06-03T10:31:00Z", "event_type": "logout"},
    ]


def test_json_log_parser_detects_json_lines() -> None:
    parser = JsonLogParser()
    sample = '{"a": 1}\n{"b": 2}'

    assert parser.detect(sample) == 1.0
    assert parser.parse(sample) == [{"a": 1}, {"b": 2}]


def test_json_log_parser_detects_sample_json_file() -> None:
    parser = JsonLogParser()
    sample_file = Path(__file__).resolve().parents[1].parent / "samples" / "sample.json"
    content = sample_file.read_text(encoding="utf-8")

    assert parser.detect(content) == 1.0
    assert parser.parse(content)[0]["event_type"] == "failed_login"
