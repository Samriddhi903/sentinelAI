import re
from .base_parser import BaseParser
from typing import Any


class NginxParser(BaseParser):
    name = "nginx"

    # Combined log format with optional user agent
    _pattern = re.compile(
        r'(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)[^\"]*" (?P<status>\d{3}) \S+(?: "[^"]*" "(?P<agent>[^"]*)")?'
    )

    def detect(self, text: str) -> float:
        lines = [l.strip() for l in text.splitlines() if l.strip()]
        if not lines:
            return 0.0

        def full_nginx_match(line: str) -> bool:
            m = self._pattern.fullmatch(line)
            return bool(m and m.group("agent"))

        full_matches = sum(1 for l in lines if full_nginx_match(l))
        if full_matches == len(lines):
            return 1.0

        def partial_nginx_match(line: str) -> bool:
            m = self._pattern.search(line)
            return bool(m and m.group("agent"))

        partial_matches = sum(1 for l in lines if partial_nginx_match(l))
        if partial_matches == 0:
            return 0.0
        return min(1.0, partial_matches / len(lines) * 0.9)

    def parse(self, text: str) -> list[dict[str, Any]]:
        events = []
        for l in text.splitlines():
            m = self._pattern.search(l)
            if m:
                events.append(
                    {
                        "raw": l,
                        "timestamp": m.group("time"),
                        "client_ip": m.group("ip"),
                        "user": None if m.group("user") == "-" else m.group("user"),
                        "method": m.group("method"),
                        "path": m.group("path"),
                        "status_code": m.group("status"),
                        "user_agent": m.group("agent"),
                    }
                )
        return events

    def normalize(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        normalized = []
        for e in events:
            normalized.append(
                {
                    "event_type": "http_request",
                    "timestamp": e.get("timestamp"),
                    "source": self.name,
                    "ip": e.get("client_ip"),
                    "user": e.get("user"),
                    "metadata": {
                        "method": e.get("method"),
                        "path": e.get("path"),
                        "status_code": e.get("status_code"),
                        "user_agent": e.get("user_agent"),
                    },
                }
            )
        return normalized
