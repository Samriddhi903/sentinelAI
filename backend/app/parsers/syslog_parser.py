import re
from .base_parser import BaseParser
from typing import Any


class SyslogParser(BaseParser):
    name = "syslog"

    _pattern = re.compile(r"^\w{3} +\d{1,2} \d{2}:\d{2}:\d{2} ")

    def detect(self, text: str) -> float:
        lines = text.splitlines()
        if not lines:
            return 0.0
        matches = sum(1 for l in lines if self._pattern.match(l))
        score = matches / len(lines)
        return min(1.0, score * 0.95)

    def parse(self, text: str) -> list[dict[str, Any]]:
        events = []
        for l in text.splitlines():
            if self._pattern.match(l):
                events.append({"raw": l})
        return events

    def normalize(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [{"message": e.get("raw")} for e in events]
