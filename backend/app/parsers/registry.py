from typing import List, Tuple

from .base_parser import BaseParser


class ParserRegistry:
    """Registry for parser instances."""

    def __init__(self) -> None:
        self._parsers: List[BaseParser] = []

    def register_parser(self, parser: BaseParser) -> None:
        self._parsers.append(parser)

    def detect_parser(self, text: str) -> Tuple[str | None, float, list[dict[str, float]]]:
        scores: list[dict[str, float]] = []
        for p in self._parsers:
            try:
                score = float(p.detect(text))
            except Exception:
                score = 0.0
            scores.append({"format": p.name, "confidence": min(1.0, max(0.0, score))})

        scores.sort(key=lambda t: t["confidence"], reverse=True)
        if not scores:
            return None, 0.0, []

        best = scores[0]
        alternatives = scores[1:]
        return best["format"], best["confidence"], alternatives

    def get_parser(self, name: str) -> BaseParser | None:
        for p in self._parsers:
            if p.name == name:
                return p
        return None
