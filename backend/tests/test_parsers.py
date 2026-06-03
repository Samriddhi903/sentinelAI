from app.parsers.registry import ParserRegistry
from app.parsers.nginx_parser import NginxParser
from app.parsers.apache_parser import ApacheParser
from app.parsers.syslog_parser import SyslogParser
from app.parsers.json_log_parser import JsonLogParser


def test_parser_registry_detects_nginx_sample() -> None:
    registry = ParserRegistry()
    registry.register_parser(NginxParser())
    registry.register_parser(ApacheParser())
    registry.register_parser(SyslogParser())
    registry.register_parser(JsonLogParser())

    sample = '192.168.1.1 - - [03/Jun/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 612'
    name, confidence, alternatives = registry.detect_parser(sample)

    assert name in ("nginx", "apache")
    assert confidence > 0.0
    assert isinstance(alternatives, list)
