from fastapi import APIRouter

from app.dependencies import AnomalyDetectionServiceDep, AnomalyRepositoryDep

router = APIRouter(prefix="/upload", tags=["anomaly"])


@router.get("/{upload_id}/anomaly")
async def get_anomaly(
    upload_id: str,
    anomaly_service: AnomalyDetectionServiceDep,
    anomaly_repository: AnomalyRepositoryDep,
):
    # If anomaly was already computed, return latest.
    latest = await anomaly_repository.find_latest_by_upload_id(upload_id)
    if latest is not None:
        return {
            "upload_id": upload_id,
            "anomaly_score": int(latest.get("anomaly_score", 0)),
            "is_anomalous": bool(latest.get("is_anomalous", False)),
        }

    # Otherwise compute it (must not crash analysis).
    computed = await anomaly_service.run_for_upload(upload_id)
    return computed

