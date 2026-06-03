import re
from .base_parser import BaseParser
from typing import Any


class NginxParser(BaseParser):
    name = "nginx"

    _pattern = re.compile(r"^(?P<ip>\S+) \S+ \S+ \[.*\] \"[A-Z]+ .* HTTP/1\.[01]\" \d{3} \d+")

    def detect(self, text: str) -> float:
        lines = text.splitlines()
        matches = sum(1 for l in lines if self._pattern.match(l))
        if not lines:
            return 0.0
        score = matches / len(lines)
        return min(1.0, score * 1.0)

    def parse(self, text: str) -> list[dict[str, Any]]:
        events = []
        for l in text.splitlines():
            m = self._pattern.match(l)
            if m:
                events.append({"raw": l, "ip": m.group("ip")})
        return events

    def normalize(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [{"source.ip": e.get("ip"), "message": e.get("raw")} for e in events]
