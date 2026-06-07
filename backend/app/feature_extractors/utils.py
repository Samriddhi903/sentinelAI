from __future__ import annotations

import re
from typing import Pattern
from urllib.parse import unquote

# Reusable compiled regex patterns
SQLI_PATTERNS_RAW = [
    r"\bOR\b\s+1=1",
    r"'\s+OR\s+'",
    r"'\s+OR\s+'1'\s*=\s*1",
    r"UNION\s+(ALL\s+)?SELECT",
    r"information_schema",
    r"\bsleep\(",
    r"benchmark\(",
    r"xp_cmdshell",
]
SQLI_PATTERNS: list[Pattern] = [re.compile(p, re.IGNORECASE) for p in SQLI_PATTERNS_RAW]

XSS_PATTERNS_RAW = [r"<script", r"javascript:", r"\balert\(", r"onerror=", r"onload=", r"document\.cookie", r"\beval\("]
XSS_PATTERNS: list[Pattern] = [re.compile(p, re.IGNORECASE) for p in XSS_PATTERNS_RAW]

SENSITIVE_FILES = ["/etc/shadow", "/etc/passwd", "authorized_keys", "SAM", "SYSTEM", "ntds.dit"]
RECON_COMMANDS = [r"\bnmap\b", r"\bmasscan\b", r"\bnetstat\b", r"\barp\b", r"\bipconfig\b", r"\bwhoami\b", r"\broute\b", r"\btraceroute\b"]
RECON_PATTERNS: list[Pattern] = [re.compile(p, re.IGNORECASE) for p in RECON_COMMANDS]

CRITICAL_FILES = ["/etc/passwd", "/etc/shadow", "authorized_keys"]


def _normalize_input(text: str) -> str:
    if not text:
        return ""
    # decode URL-encoded content for detection
    try:
        decoded = unquote(text)
    except Exception:
        decoded = text
    return decoded


def is_sqli(text: str) -> bool:
    s = _normalize_input(text or "")
    for patt in SQLI_PATTERNS:
        if patt.search(s):
            return True
    return False


def is_xss(text: str) -> bool:
    s = _normalize_input(text or "")
    for patt in XSS_PATTERNS:
        if patt.search(s):
            return True
    return False


def is_sensitive_file(path: str) -> bool:
    if not path:
        return False
    s = _normalize_input(path)
    for f in SENSITIVE_FILES:
        if f.lower() in s.lower():
            return True
    return False


def is_critical_file(path: str) -> bool:
    if not path:
        return False
    s = _normalize_input(path)
    for f in CRITICAL_FILES:
        if f.lower() in s.lower():
            return True
    return False


def is_recon_command(command: str) -> bool:
    if not command:
        return False
    s = command
    for patt in RECON_PATTERNS:
        if patt.search(s):
            return True
    return False
