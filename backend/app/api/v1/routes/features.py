from fastapi import APIRouter

from app.dependencies import FeatureEngineeringServiceDep
from app.schemas.features import FeaturesExtractionResponse

router = APIRouter(prefix="/upload", tags=["features"])


@router.post("/{upload_id}/features", response_model=FeaturesExtractionResponse)
async def extract_features(upload_id: str, service: FeatureEngineeringServiceDep) -> FeaturesExtractionResponse:
    return await service.extract_features(upload_id)
