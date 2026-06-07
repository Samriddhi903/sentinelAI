from typing import Any


class InMemoryFeatureRepository:
    def __init__(self) -> None:
        self.features: list[dict[str, Any]] = []

    async def ensure_indexes(self) -> None:
        return None

    async def insert_features(self, features: list[dict[str, Any]]) -> None:
        for f in features:
            self.features.append(f)

    async def find_by_upload_id(self, upload_id: str) -> list[dict[str, Any]]:
        return [f for f in self.features if f.get("upload_id") == upload_id]
