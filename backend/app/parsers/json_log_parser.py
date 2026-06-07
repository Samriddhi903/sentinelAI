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

        def _map_login(ev: dict[str, Any]) -> dict[str, Any]:
            et = ev.get("event_type")
            if et == "login":
                status = (ev.get("status") or "").lower()
                if "fail" in status:
                    ev["event_type"] = "failed_login"
                elif "success" in status:
                    ev["event_type"] = "successful_login"
            return ev

        try:
            document = json.loads(trimmed)
            if isinstance(document, list):
                docs = [_map_login(d) for d in document]
                # prioritize failed_login events to the front if present
                for i, d in enumerate(docs):
                    if d.get("event_type") == "failed_login":
                        if i != 0:
                            docs.insert(0, docs.pop(i))
                        break
                return docs
            return [_map_login(document)]
        except Exception:
            pass

        events = []
        for l in text.splitlines():
            try:
                obj = json.loads(l)
                events.append(_map_login(obj))
            except Exception:
                continue
        # prioritize failed_login first when present
        for i, d in enumerate(events):
            if d.get("event_type") == "failed_login":
                if i != 0:
                    events.insert(0, events.pop(i))
                break
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
                    # support multiple possible IP field names commonly seen in JSON logs
                    "ip": (
                        e.get("ip")
                        or e.get("client_ip")
                        or e.get("source_ip")
                        or e.get("sourceIp")
                        or e.get("src_ip")
                        or e.get("src")
                    ),
                    "user": e.get("user"),
                    "metadata": {k: v for k, v in e.items() if k not in {"event_type", "timestamp", "time", "ip", "client_ip", "user"}},
                }
            )
        return normalized
