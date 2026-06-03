from datetime import datetime
from typing import Any

from app.parsers.registry import ParserRegistry


class FormatDetectionService:
    """Detects log format using registered parsers."""

    def __init__(self, registry: ParserRegistry) -> None:
        self._registry = registry

    def detect_format(self, text: str) -> dict[str, Any]:
        name, confidence, alternatives = self._registry.detect_parser(text)
        return {
            "format": name,
            "confidence": float(confidence),
            "alternatives": alternatives,
        }
