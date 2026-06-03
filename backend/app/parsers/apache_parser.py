import re
from .base_parser import BaseParser
from typing import Any


class ApacheParser(BaseParser):
    name = "apache"

    _pattern = re.compile(
        r'(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)[^\"]*" (?P<status>\d{3}) \d+(?:\s*)$'
    )
    _partial_pattern = re.compile(
        r'(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)[^\"]*" (?P<status>\d{3}) \d+'
    )

    def detect(self, text: str) -> float:
        lines = [l.strip() for l in text.splitlines() if l.strip()]
        if not lines:
            return 0.0

        full_matches = sum(1 for l in lines if self._pattern.fullmatch(l))
        if full_matches == len(lines):
            return 1.0

        partial_matches = sum(1 for l in lines if self._partial_pattern.search(l))
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
                    },
                }
            )
        return normalized
