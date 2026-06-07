import re
from .base_parser import BaseParser
from typing import Any


class SyslogParser(BaseParser):
    name = "syslog"

    _pattern = re.compile(r'^(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) (?P<host>\S+) (?P<proc>[\w\-/]+)(?:\[\d+\])?: (?P<msg>.*)')
    _ip_pattern = re.compile(r"\b(?:from\s+|SRC=)(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b", re.IGNORECASE)
    _generic_ip_pattern = re.compile(r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})")

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
            message = e.get("message") or ""
            process = e.get("process") or ""
            user = None
            if process.lower() == "sudo":
                sudo_user_match = re.match(r"^(\S+)", message.strip())
                if sudo_user_match:
                    user = sudo_user_match.group(1)
            normalized.append(
                {
                    "event_type": "syslog_event",
                    "timestamp": e.get("timestamp"),
                    "source": self.name,
                    "ip": self._extract_ip(message),
                    "user": user,
                    "metadata": {
                        "hostname": e.get("hostname"),
                        "process": process,
                        "message": message,
                    },
                }
            )
        return normalized

    def _extract_ip(self, message: str) -> str | None:
        if not message:
            return None
        match = self._ip_pattern.search(message)
        if match:
            return match.group("ip")
        # fallback: find any IPv4-like pattern
        m2 = self._generic_ip_pattern.search(message)
        return m2.group("ip") if m2 else None
