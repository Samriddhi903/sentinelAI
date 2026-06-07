from __future__ import annotations

from typing import Any, List, Dict
from .apache import SQLI_PATTERNS, XSS_PATTERNS, TRAVERSAL, ENUM_PATHS, SENSITIVE_FILES, WEBSHELLS
from .base import BaseFeatureExtractor


class NginxFeatureExtractor(BaseFeatureExtractor):
    name = "nginx"

    def extract(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # Reuse Apache logic - nginx has similar features
        from .apache import ApacheFeatureExtractor

        return ApacheFeatureExtractor().extract(events)
