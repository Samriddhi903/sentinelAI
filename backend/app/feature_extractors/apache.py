from __future__ import annotations

from typing import Any, List, Dict
from collections import defaultdict
import re
from urllib.parse import unquote, urlparse

from .utils import is_sqli, is_xss

from .base import BaseFeatureExtractor


SQLI_PATTERNS = [r"\bOR\b\s+1=1", r"'\s+OR\s+'", r"UNION\s+SELECT", r"information_schema", r"\bsleep\(", r"benchmark\(", r"xp_cmdshell"]
XSS_PATTERNS = [r"<script", r"javascript:", r"\balert\(", r"onerror=", r"onload="]
TRAVERSAL = ["../", "..\\\\", "%2e%2e", "%252e%252e"]
ENUM_PATHS = ["/admin", "/administrator", "/wp-admin", "/phpmyadmin", "/server-status"]
SENSITIVE_FILES = [".env", ".git/config", "/etc/passwd", "/etc/shadow", "wp-config.php"]
WEBSHELLS = ["shell.php", "cmd.php", "c99.php", "r57.php"]


class ApacheFeatureExtractor(BaseFeatureExtractor):
    name = "apache"

    def extract(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        per_ip: Dict[str, Dict[str, Any]] = defaultdict(lambda: defaultdict(int))

        for e in events:
            ip = e.get("ip") or "unknown"
            per = per_ip[ip]
            metadata = e.get("metadata", {})
            path = metadata.get("path")
            status = metadata.get("status_code")

            # stats
            per["request_count"] += 1
            if path:
                per.setdefault("paths", set()).add(path)

            # status buckets
            try:
                code = int(status)
            except Exception:
                code = 0
            if 100 <= code < 200:
                per["status_1xx"] += 1
            elif 200 <= code < 300:
                per["status_2xx"] += 1
            elif 300 <= code < 400:
                per["status_3xx"] += 1
            elif 400 <= code < 500:
                per["status_4xx"] += 1
            elif 500 <= code < 600:
                per["status_5xx"] += 1

            # security detections via simple pattern checks
            if path:
                decoded_path = unquote(path)
                for p in ENUM_PATHS:
                    if p in decoded_path:
                        per["directory_enumeration_count"] += 1
                for s in SENSITIVE_FILES:
                    if s in decoded_path:
                        per["sensitive_file_probe_count"] += 1
                for w in WEBSHELLS:
                    if w in decoded_path:
                        per["webshell_access_count"] += 1
                for t in TRAVERSAL:
                    if t in decoded_path:
                        per["path_traversal_count"] += 1

            raw = e.get("metadata", {}).get("raw") or e.get("raw") or path or ""
            decoded_raw = unquote(str(raw))
            candidates = [str(raw), decoded_raw]
            if path:
                candidates.append(path)
                candidates.append(decoded_path)

            request_component = ""
            if isinstance(raw, str):
                parts = raw.split()
                if len(parts) >= 2:
                    request_component = parts[1]
                    candidates.append(request_component)
                    candidates.append(unquote(request_component))
            if path and path != request_component:
                candidates.append(path)
                candidates.append(decoded_path)

            # parse any URL/query components for dedicated matching
            for source in list(candidates):
                try:
                    parsed = urlparse(source)
                    if parsed.path:
                        candidates.append(parsed.path)
                        candidates.append(unquote(parsed.path))
                    if parsed.query:
                        candidates.append(parsed.query)
                        candidates.append(unquote(parsed.query))
                except Exception:
                    continue

            if any(is_sqli(str(item)) for item in candidates):
                per["sqli_attempt_count"] += 1
            if any(is_xss(str(item)) for item in candidates):
                per["xss_attempt_count"] += 1

            # brute force detection: count 401s per (ip, path)
            status_code = None
            try:
                status_code = int(metadata.get("status_code") or 0)
            except Exception:
                status_code = 0
            if status_code == 401:
                per.setdefault("login_401_count", 0)
                per["login_401_count"] += 1
                per.setdefault("failed_login_count", 0)
                per["failed_login_count"] += 1

        features: List[Dict[str, Any]] = []
        # build per-ip features
        for ip, stats in per_ip.items():
            paths = stats.pop("paths", set())
            # finalize brute force metric
            brute_count = stats.get("login_401_count", 0)
            features.append({
                "source_ip": ip,
                "request_count": stats.get("request_count", 0),
                "unique_paths": len(paths),
                "unique_source_ips": len(per_ip),
                "status_2xx": stats.get("status_2xx", 0),
                "status_3xx": stats.get("status_3xx", 0),
                "status_4xx": stats.get("status_4xx", 0),
                "status_5xx": stats.get("status_5xx", 0),
                "error_rate": float((stats.get("status_4xx", 0) + stats.get("status_5xx", 0)) / max(1, stats.get("request_count", 1))),
                "sqli_attempt_count": stats.get("sqli_attempt_count", 0),
                "xss_attempt_count": stats.get("xss_attempt_count", 0),
                "path_traversal_count": stats.get("path_traversal_count", 0),
                "directory_enumeration_count": stats.get("directory_enumeration_count", 0),
                "sensitive_file_probe_count": stats.get("sensitive_file_probe_count", 0),
                "webshell_access_count": stats.get("webshell_access_count", 0),
                "brute_force_attempt_count": brute_count,
                "login_401_count": brute_count,
                "failed_login_count": stats.get("failed_login_count", 0),
            })

        # no global summary here; feature documents are per-source_ip only

        return features
