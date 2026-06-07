from __future__ import annotations

from typing import Any, List, Dict
from collections import defaultdict

from .base import BaseFeatureExtractor


class JsonFeatureExtractor(BaseFeatureExtractor):
    name = "json"

    def extract(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        per_ip = defaultdict(lambda: defaultdict(int))

        from .utils import is_sensitive_file, is_recon_command, is_critical_file

        for e in events:
            ip = e.get("ip") or "unknown"
            et = (e.get("event_type") or "").lower()
            per = per_ip[ip]

            if et in ("failed_login", "login_failed") or ("failed" in et and "login" in et):
                per["failed_login_count"] += 1
            if et in ("successful_login", "login_success", "accepted") or ("success" in et and "login" in et):
                per["successful_login_count"] += 1
            if et in ("port_scan", "scan", "reconnaissance") or "scan" in et:
                per["port_scan_count"] += 1

            # sensitive file access may appear in metadata under multiple keys
            meta = e.get("metadata") or {}
            file_path = meta.get("path") or meta.get("file") or meta.get("filename") or meta.get("target")
            if is_sensitive_file(file_path):
                per["sensitive_file_access_count"] += 1
            if et == "command_execution":
                cmd = meta.get("command") or ""
                if is_recon_command(cmd):
                    per["reconnaissance_count"] += 1
                per["command_execution_count"] += 1
            if et == "privilege_escalation":
                per["privilege_escalation_count"] += 1
            if et == "file_modification":
                if is_critical_file(file_path):
                    per["critical_file_modification_count"] += 1

        features: List[Dict[str, Any]] = []
        for ip, stats in per_ip.items():
            features.append({
                "source_ip": ip,
                "failed_login_count": stats.get("failed_login_count", 0),
                "successful_login_count": stats.get("successful_login_count", 0),
                "port_scan_count": stats.get("port_scan_count", 0),
                "sensitive_file_access_count": stats.get("sensitive_file_access_count", 0),
                "command_execution_count": stats.get("command_execution_count", 0),
                "reconnaissance_count": stats.get("reconnaissance_count", 0),
                "critical_file_modification_count": stats.get("critical_file_modification_count", 0),
                "privilege_escalation_count": stats.get("privilege_escalation_count", 0),
            })

        return features
