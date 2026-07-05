from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.models.pipeline import FeatureDocument
from app.models.upload import UploadStatus
from app.repositories.event_repository import EventRepository
from app.repositories.feature_repository import FeatureRepository
from app.repositories.upload_repository import UploadRepository


class FeatureEngineeringService:
    def __init__(
        self,
        upload_repository: UploadRepository,
        event_repository: EventRepository,
        feature_repository: FeatureRepository,
    ) -> None:
        self._upload_repository = upload_repository
        self._event_repository = event_repository
        self._feature_repository = feature_repository

    async def extract_features(self, upload_id: str) -> dict[str, Any]:
        document = await self._upload_repository.find_by_upload_id(upload_id)
        if document is None:
            from app.core.exceptions import UploadNotFoundError

            raise UploadNotFoundError(upload_id)

        if document["status"] != UploadStatus.NORMALIZED.value:
            from app.core.exceptions import FileStorageError

            raise FileStorageError("upload must be normalized before feature extraction")

        claimed = await self._upload_repository.transition_status(
            upload_id,
            expected={UploadStatus.NORMALIZED},
            target=UploadStatus.FEATURE_EXTRACTING,
        )
        if claimed is None:
            from app.core.exceptions import FileStorageError

            raise FileStorageError("upload must be normalized before feature extraction")

        try:
            events = await self._event_repository.find_by_upload_id(upload_id)

            # select extractors based on event types present
            from app.feature_extractors.factory import FeatureExtractorFactory

            extractors = FeatureExtractorFactory.get_extractors(events)

            # count unique source IPs across events
            unique_source_ips_count = len({e.get("ip") for e in events if e.get("ip")})

            raw_features: list[dict[str, Any]] = []
            for ext in extractors:
                try:
                    ext_feats = ext.extract(events)
                except Exception:
                    ext_feats = []
                raw_features.extend(ext_feats)

            # merge features by source_ip (skip any extractor-provided global docs)
            merged: dict[str, dict[str, Any]] = {}
            for f in raw_features:
                src = f.get("source_ip")
                if not src or src == "_global":
                    continue
                if src not in merged:
                    merged[src] = {
                        k: v
                        for k, v in f.items()
                        if k not in {"feature_id", "upload_id", "generated_at"}
                    }
                    continue

                base = merged[src]
                for k, v in f.items():
                    if k in {"feature_id", "upload_id", "generated_at", "source_ip"}:
                        continue
                    if isinstance(v, (int, float)):
                        base[k] = int(base.get(k, 0) + v)
                    else:
                        # fallback: keep first-seen non-numeric
                        base.setdefault(k, v)

            features: list[dict[str, Any]] = []
            for ip, data in merged.items():
                data.setdefault("source_ip", ip)
                data.setdefault("unique_source_ips", unique_source_ips_count)
                data.setdefault("feature_id", str(uuid4()))
                data.setdefault("upload_id", upload_id)
                data.setdefault("generated_at", datetime.now(UTC))
                features.append(data)

            typed_features = [FeatureDocument.model_validate(feature) for feature in features]
            await self._feature_repository.insert_features(
                [feature.model_dump() for feature in typed_features]
            )

            generated_at = datetime.now(UTC)
            updated = await self._upload_repository.update_feature_extraction_result(
                upload_id, status=UploadStatus.FEATURES_GENERATED, generated_at=generated_at
            )
        except Exception:
            await self._upload_repository.transition_status(
                upload_id,
                expected={UploadStatus.FEATURE_EXTRACTING},
                target=UploadStatus.FAILED,
            )
            raise

        if updated is None:
            raise Exception("upload record missing after feature extraction")

        return {
            "upload_id": updated["upload_id"],
            "status": updated["status"],
            "generated_at": generated_at,
        }
