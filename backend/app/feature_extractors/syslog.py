from __future__ import annotations

from typing import Any, List, Dict
import re

from .base import BaseFeatureExtractor


class SyslogFeatureExtractor(BaseFeatureExtractor):
    name = "syslog"

    FAILED_PATTERNS = [r"failed password", r"failure", r"authentication failure", r"invalid user"]
    SUCCESS_PATTERNS = [r"accepted password", r"session opened", r"session opened for user"]
    SUDO_PATTERNS = [r"sudo:", r"sudo"]
    NEWUSER_PATTERNS = [r"new user", r"useradd", r"created user"]
    PASSWD_CHANGE = [r"password changed", r"passwd"]
    SERVICE_FAIL = [r"failed with result", r"failed with result 'exit-code'", r"service\b.*failed", r"\bfailed with result\b"]
    CRON_SUSPICIOUS = [r"curl .* \| bash", r"wget .* \| sh", r"curl .*payload", r"payload\.sh"]
    FIREWALL_PATTERNS = [r"blocked", r"denied", r"ufw", r"iptables", r"UFW BLOCK", r"DROP", r"IN=", r"SRC="]

    def extract(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        per_ip: Dict[str, Dict[str, Any]] = {}
        unique_login_ips = set()
        last_remote_ip: str | None = None

        sorted_events = sorted(events, key=lambda e: str(e.get("timestamp") or ""))

        for e in sorted_events:
            event_ip = e.get("ip")
            if event_ip:
                last_remote_ip = event_ip

            ip = event_ip or last_remote_ip or "unknown"
            if ip not in per_ip:
                per_ip[ip] = {"_seen_cron_cmds": set()}
            per = per_ip[ip]

            metadata = e.get("metadata") or {}
            msg = (metadata.get("message") or "").lower()
            proc = (metadata.get("process") or "").lower()
            searchable = f"{proc}: {msg}" if proc else msg
            et = (e.get("event_type") or "").lower()

            if et == "syslog_event":
                if any(re.search(p, msg) for p in self.FAILED_PATTERNS):
                    per["failed_login_count"] = per.get("failed_login_count", 0) + 1
                if any(re.search(p, msg) for p in self.SUCCESS_PATTERNS):
                    per["successful_login_count"] = per.get("successful_login_count", 0) + 1
                    unique_login_ips.add(ip)
                if proc == "sudo" or any(re.search(p, searchable) for p in self.SUDO_PATTERNS):
                    per["sudo_event_count"] = per.get("sudo_event_count", 0) + 1
                if any(re.search(p, searchable) for p in self.FIREWALL_PATTERNS):
                    per["firewall_block_count"] = per.get("firewall_block_count", 0) + 1
                if any(re.search(p, searchable) for p in self.NEWUSER_PATTERNS):
                    per["new_user_count"] = per.get("new_user_count", 0) + 1
                if any(re.search(p, searchable) for p in self.PASSWD_CHANGE):
                    per["password_change_count"] = per.get("password_change_count", 0) + 1
                if any(re.search(p, msg) for p in self.SERVICE_FAIL):
                    if not any(re.search(fp, msg) for fp in self.FAILED_PATTERNS):
                        per["service_failure_count"] = per.get("service_failure_count", 0) + 1
                if any(re.search(p, msg) for p in self.CRON_SUSPICIOUS):
                    seen = per["_seen_cron_cmds"]
                    key = msg.strip()
                    if key not in seen:
                        seen.add(key)
                        per["suspicious_cron_count"] = per.get("suspicious_cron_count", 0) + 1

        features: List[Dict[str, Any]] = []
        for ip, stats in per_ip.items():
            features.append({
                "source_ip": ip,
                "failed_login_count": stats.get("failed_login_count", 0),
                "successful_login_count": stats.get("successful_login_count", 0),
                "root_login_count": 0,
                "unique_login_ips": len(unique_login_ips),
                "repeated_failed_login_ips": 1 if stats.get("failed_login_count", 0) > 3 else 0,
                "brute_force_detected": stats.get("failed_login_count", 0) > 5,
                "sudo_event_count": stats.get("sudo_event_count", 0),
                "firewall_block_count": stats.get("firewall_block_count", 0),
                "privilege_escalation_count": 0,
                "new_user_count": stats.get("new_user_count", 0),
                "password_change_count": stats.get("password_change_count", 0),
                "service_failure_count": stats.get("service_failure_count", 0),
                "suspicious_cron_count": stats.get("suspicious_cron_count", 0),
            })

        # no global summary here; feature documents are per-source_ip only

        return features
