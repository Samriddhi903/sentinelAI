import json
from .base_parser import BaseParser
from typing import Any


class JsonLogParser(BaseParser):
    name = "json"

    def detect(self, text: str) -> float:
        lines = [l for l in text.splitlines() if l.strip()]
        if not lines:
            return 0.0
        parsed = 0
        for l in lines[:50]:
            try:
                json.loads(l)
                parsed += 1
            except Exception:
                continue
        return min(1.0, parsed / len(lines))

    def parse(self, text: str) -> list[dict[str, Any]]:
        events = []
        for l in text.splitlines():
            try:
                obj = json.loads(l)
                events.append(obj)
            except Exception:
                continue
        return events

    def normalize(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return events
