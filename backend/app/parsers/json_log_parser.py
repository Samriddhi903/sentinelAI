import json
from .base_parser import BaseParser
from typing import Any


class JsonLogParser(BaseParser):
    name = "json"

    def detect(self, text: str) -> float:
        trimmed = text.strip()
        if not trimmed:
            return 0.0

        try:
            json.loads(trimmed)
            return 1.0
        except Exception:
            pass

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
        trimmed = text.strip()
        if not trimmed:
            return []

        try:
            document = json.loads(trimmed)
            if isinstance(document, list):
                return document
            return [document]
        except Exception:
            pass

        events = []
        for l in text.splitlines():
            try:
                obj = json.loads(l)
                events.append(obj)
            except Exception:
                continue
        return events

    def normalize(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        normalized = []
        for e in events:
            # map common fields if present
            normalized.append(
                {
                    "event_type": e.get("event_type") or "json_event",
                    "timestamp": e.get("timestamp") or e.get("time"),
                    "source": self.name,
                    "ip": e.get("ip") or e.get("client_ip"),
                    "user": e.get("user"),
                    "metadata": {k: v for k, v in e.items() if k not in {"event_type", "timestamp", "time", "ip", "client_ip", "user"}},
                }
            )
        return normalized
