from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BaseParser(ABC):
    """Abstract base parser interface."""

    name: str

    @abstractmethod
    def detect(self, text: str) -> float:
        """Return a confidence score between 0.0 and 1.0 that this parser matches the text."""

    @abstractmethod
    def parse(self, text: str) -> list[dict[str, Any]]:
        """Parse the text into structured events."""

    @abstractmethod
    def normalize(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Normalize parsed events to the internal event schema."""
