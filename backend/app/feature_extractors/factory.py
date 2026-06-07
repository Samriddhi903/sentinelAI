from __future__ import annotations

from typing import List, Dict

from .apache import ApacheFeatureExtractor
from .nginx import NginxFeatureExtractor
from .syslog import SyslogFeatureExtractor
from .json_extractor import JsonFeatureExtractor


class FeatureExtractorFactory:
    """Returns appropriate extractor(s) for a set of normalized events."""

    @staticmethod
    def get_extractors(events: List[Dict]):
        # naive approach: if majority of events are of a type, use that extractor
        types = [e.get("event_type") for e in events]
        typeset = set(t for t in types if t)
        # also inspect metadata for HTTP-like fields
        has_http_meta = any((e.get("metadata", {}).get("status_code") is not None) or (e.get("metadata", {}).get("path") is not None) for e in events)
        extractors = []
        if "http_request" in typeset or has_http_meta:
            # use apache extractor for HTTP-like events
            extractors.append(ApacheFeatureExtractor())
        if "syslog_event" in typeset:
            extractors.append(SyslogFeatureExtractor())
        if any(t and t.startswith("json") or t in ("failed_login", "port_scan", "successful_login") for t in typeset):
            extractors.append(JsonFeatureExtractor())

        if not extractors:
            # default to json extractor for generic events
            extractors.append(JsonFeatureExtractor())

        return extractors
