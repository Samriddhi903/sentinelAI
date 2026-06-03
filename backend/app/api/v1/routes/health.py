"""Health check API routes."""

from fastapi import APIRouter, Response

from app.dependencies import HealthServiceDep
from app.schemas.health import LivenessResponse, ReadinessResponse

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/live", response_model=LivenessResponse)
async def liveness(health_service: HealthServiceDep) -> LivenessResponse:
    return health_service.get_liveness()


@router.get("/ready", response_model=ReadinessResponse)
async def readiness(
    health_service: HealthServiceDep,
    response: Response,
) -> ReadinessResponse:
    readiness_result, status_code = await health_service.get_readiness()
    response.status_code = status_code
    return readiness_result
