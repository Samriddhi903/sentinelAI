import re
from .base_parser import BaseParser
from typing import Any


class SyslogParser(BaseParser):
    name = "syslog"

    _pattern = re.compile(r'^(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) (?P<host>\S+) (?P<proc>[\w\-/]+)(?:\[\d+\])?: (?P<msg>.*)')

    def detect(self, text: str) -> float:
        lines = [l for l in text.splitlines() if l.strip()]
        if not lines:
            return 0.0
        matches = sum(1 for l in lines if self._pattern.search(l))
        return min(1.0, matches / len(lines))

    def parse(self, text: str) -> list[dict[str, Any]]:
        events = []
        for l in text.splitlines():
            m = self._pattern.search(l)
            if m:
                ts = f"{m.group('month')} {m.group('day')} {m.group('time')}"
                events.append(
                    {
                        "raw": l,
                        "timestamp": ts,
                        "hostname": m.group("host"),
                        "process": m.group("proc"),
                        "message": m.group("msg"),
                    }
                )
        return events

    def normalize(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        normalized = []
        for e in events:
            normalized.append(
                {
                    "event_type": "syslog_event",
                    "timestamp": e.get("timestamp"),
                    "source": self.name,
                    "ip": None,
                    "user": None,
                    "metadata": {
                        "hostname": e.get("hostname"),
                        "process": e.get("process"),
                        "message": e.get("message"),
                    },
                }
            )
        return normalized
