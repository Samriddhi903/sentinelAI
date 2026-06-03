from datetime import datetime
from typing import Any

from app.parsers.registry import ParserRegistry


class FormatDetectionService:
    """Detects log format using registered parsers."""

    def __init__(self, registry: ParserRegistry) -> None:
        self._registry = registry

    def detect_format(self, text: str) -> dict[str, Any]:
        name, confidence, alternatives = self._registry.detect_parser(text)
        if len(alternatives) > 0 and abs(confidence - alternatives[0]["confidence"]) < 0.1:
            return {
                "format": "unknown",
                "confidence": 0.5,
                "alternatives": [
                    {"format": name, "confidence": confidence},
                    {"format": alternatives[0]["format"], "confidence": alternatives[0]["confidence"]},
                    *alternatives[1:],
                ],
            }

        return {
            "format": name,
            "confidence": float(confidence),
            "alternatives": alternatives,
        }
