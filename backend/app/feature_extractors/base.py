from __future__ import annotations

from typing import Any, List, Dict


class BaseFeatureExtractor:
    """Base class for feature extractors.

    Subclasses should implement `extract` which accepts the full list of
    normalized events for an upload and returns a list of feature documents
    (one per IP plus optional global features).
    """

    name: str = "base"

    def extract(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        raise NotImplementedError()
