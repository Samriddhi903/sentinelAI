from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest

from app.core.logging import get_logger
from app.repositories.anomaly_repository import AnomalyRepository
from app.repositories.feature_repository import FeatureRepository


logger = get_logger(__name__)


FEATURE_VECTOR_KEYS: list[str] = [
    "failed_login_count",
    "successful_login_count",
    "unique_source_ips",
    "sqli_attempt_count",
    "xss_attempt_count",
    "path_traversal_count",
    "directory_enumeration_count",
    "sensitive_file_probe_count",
    "brute_force_attempt_count",
    "privilege_escalation_count",
    "suspicious_cron_count",
    "account_creation_count",
    "credential_modification_count",
    "firewall_block_count",
]


@dataclass(frozen=True)
class AnomalyResult:
    anomaly_score: int
    is_anomalous: bool


class AnomalyDetectionService:
    def __init__(
        self,
        feature_repository: FeatureRepository,
        anomaly_repository: AnomalyRepository,
        *,
        n_estimators: int = 100,
        contamination: float = 0.1,
        random_state: int = 42,
        min_samples_for_model: int = 20,
        score_threshold_anomalous: int = 60,
    ) -> None:
        self._feature_repository = feature_repository
        self._anomaly_repository = anomaly_repository
        self._model_params = dict(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
        )
        self._min_samples_for_model = min_samples_for_model
        self._score_threshold_anomalous = score_threshold_anomalous

    def _build_feature_vector_from_doc(self, doc: dict[str, Any]) -> list[float]:
        vec: list[float] = []
        for key in FEATURE_VECTOR_KEYS:
            value = doc.get(key, 0)
            try:
                vec.append(float(value))
            except Exception:
                vec.append(0.0)
        return vec

    def _build_feature_vector_from_docs(self, docs: list[dict[str, Any]]) -> np.ndarray:
        if not docs:
            return np.zeros((0, len(FEATURE_VECTOR_KEYS)), dtype=float)

        rows = [self._build_feature_vector_from_doc(d) for d in docs]
        return np.asarray(rows, dtype=float)

    def _normalize_score(self, raw_score: float) -> int:
        """Map IsolationForest raw decision score into 0-100.

        IsolationForest decision_function returns higher values for inliers.
        We transform so that lower inlier-ness -> higher anomaly score.
        """

        # convert decision_function (roughly centered) into [0, 100]
        # Use a sigmoid-like squashing; keep lightweight & stable.
        x = float(raw_score)
        mapped = 100.0 * (1.0 / (1.0 + np.exp(-x)))
        return int(np.clip(mapped, 0, 100))

    def _score_heuristically(self, docs: list[dict[str, Any]]) -> AnomalyResult:
        """Safe fallback when dataset is too small.

        Uses total event-like activity proxy by summing selected counts.
        """
        if not docs:
            return AnomalyResult(anomaly_score=0, is_anomalous=False)

        vec = self._build_feature_vector_from_docs(docs)
        sums = vec.sum(axis=1)
        activity = float(np.max(sums)) if sums.size else 0.0

        # scale: assume typical counts are small; clamp
        anomaly_score = int(np.clip(activity * 5.0, 0, 100))
        is_anomalous = anomaly_score > self._score_threshold_anomalous
        return AnomalyResult(anomaly_score=anomaly_score, is_anomalous=is_anomalous)

    def _score_with_isolation_forest(
        self,
        train_docs: list[dict[str, Any]],
        target_docs: list[dict[str, Any]],
    ) -> AnomalyResult:
        X_train = self._build_feature_vector_from_docs(train_docs)
        X_target = self._build_feature_vector_from_docs(target_docs)

        if X_train.shape[0] < self._min_samples_for_model or X_target.shape[0] == 0:
            return self._score_heuristically(target_docs)

        model = IsolationForest(**self._model_params)
        model.fit(X_train)

        # decision_function: higher => more normal
        # Convert to anomaly: raw_anomaly_signal = -decision_function
        decision = model.decision_function(X_target)
        raw_signal = -float(np.mean(decision))
        anomaly_score = self._normalize_score(raw_signal)
        is_anomalous = anomaly_score > self._score_threshold_anomalous

        return AnomalyResult(anomaly_score=anomaly_score, is_anomalous=is_anomalous)

    def _risk_label(self, anomaly_score: int) -> str:
        if anomaly_score <= 30:
            return "Normal"
        if anomaly_score <= 60:
            return "Suspicious"
        return "Highly Anomalous"

    async def run_for_upload(self, upload_id: str) -> dict[str, Any]:
        """Runs anomaly detection for a given upload_id.

        Train on all existing feature documents in Mongo (across uploads).
        """
        target_docs = await self._feature_repository.find_by_upload_id(upload_id)

        # Lightweight: use the same repository collection to fetch training docs.
        # BaseRepository exposes `.collection`.
        all_docs_cursor = self._feature_repository.collection.find({})
        train_docs: list[dict[str, Any]] = [doc async for doc in all_docs_cursor]

        try:
            if len(train_docs) < self._min_samples_for_model:
                result = self._score_heuristically(target_docs)
            else:
                result = self._score_with_isolation_forest(train_docs=train_docs, target_docs=target_docs)

            label = self._risk_label(result.anomaly_score)
            logger.info(
                "anomaly_detected",
                extra={
                    "upload_id": upload_id,
                    "anomaly_score": result.anomaly_score,
                    "is_anomalous": result.is_anomalous,
                    "label": label,
                    "train_samples": len(train_docs),
                    "target_samples": len(target_docs),
                },
            )

            if target_docs:
                source_ip = str(target_docs[0].get("source_ip", "unknown"))
            else:
                source_ip = "unknown"

            anomaly_doc = {
                "upload_id": upload_id,
                "source_ip": source_ip,
                "anomaly_score": result.anomaly_score,
                "is_anomalous": result.is_anomalous,
            }
            await self._anomaly_repository.insert_anomalies([anomaly_doc])

            return {
                "upload_id": upload_id,
                "anomaly_score": result.anomaly_score,
                "is_anomalous": result.is_anomalous,
            }
        except Exception as exc:
            # Never crash analysis.
            logger.warning(
                "anomaly_detection_failed_fallback",
                extra={"upload_id": upload_id, "error": str(exc)},
            )
            # fallback: heuristic with empty => normal
            result = self._score_heuristically(target_docs)
            if target_docs:
                source_ip = str(target_docs[0].get("source_ip", "unknown"))
            else:
                source_ip = "unknown"

            anomaly_doc = {
                "upload_id": upload_id,
                "source_ip": source_ip,
                "anomaly_score": result.anomaly_score,
                "is_anomalous": result.is_anomalous,
            }
            try:
                await self._anomaly_repository.insert_anomalies([anomaly_doc])
            except Exception:
                pass

            return {
                "upload_id": upload_id,
                "anomaly_score": result.anomaly_score,
                "is_anomalous": result.is_anomalous,
            }

