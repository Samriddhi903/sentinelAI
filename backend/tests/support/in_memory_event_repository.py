"""In-memory event repository for tests."""
from typing import Any


class InMemoryEventRepository:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    async def ensure_indexes(self) -> None:
        return None

    async def insert_events(self, events: list[dict[str, Any]]) -> None:
        for e in events:
            self.events.append(e)
