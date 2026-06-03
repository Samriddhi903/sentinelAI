from typing import List, Tuple

from .base_parser import BaseParser


class ParserRegistry:
    """Registry for parser instances."""

    def __init__(self) -> None:
        self._parsers: List[BaseParser] = []

    def register_parser(self, parser: BaseParser) -> None:
        self._parsers.append(parser)

    def detect_parser(self, text: str) -> Tuple[str | None, float, list[str]]:
        scores = []
        for p in self._parsers:
            try:
                score = p.detect(text)
            except Exception:
                score = 0.0
            scores.append((p.name, float(score)))

        scores.sort(key=lambda t: t[1], reverse=True)
        if not scores:
            return None, 0.0, []

        best = scores[0]
        alternatives = [name for name, _ in scores[1:] if _ > 0]
        return best[0], best[1], alternatives

    def get_parser(self, name: str) -> BaseParser | None:
        for p in self._parsers:
            if p.name == name:
                return p
        return None
