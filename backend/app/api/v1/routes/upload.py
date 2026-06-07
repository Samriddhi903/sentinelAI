"""Upload API routes."""

from fastapi import APIRouter, File, UploadFile

from app.dependencies import (
    UploadServiceDep,
    EventNormalizationServiceDep,
    SecurityAnalysisOrchestratorDep,
)
from app.schemas.security_analysis import SecurityAnalysisResponse, SecurityAnalysisSummaryResponse
from app.schemas.upload import UploadCreateResponse, UploadStatusResponse

router = APIRouter(prefix="/upload", tags=["upload"])


@router.post("", response_model=UploadCreateResponse, status_code=201)
async def upload_log_file(
    upload_service: UploadServiceDep,
    file: UploadFile = File(...),
) -> UploadCreateResponse:
    content = await file.read()
    return await upload_service.create_upload(file.filename, content)


@router.get("/{upload_id}/status", response_model=UploadStatusResponse)
async def get_upload_status(
    upload_id: str,
    upload_service: UploadServiceDep,
) -> UploadStatusResponse:
    return await upload_service.get_upload_status(upload_id)


@router.post("/{upload_id}/process", response_model=UploadStatusResponse)
async def process_upload(
    upload_id: str,
    upload_service: UploadServiceDep,
) -> UploadStatusResponse:
    return await upload_service.process_upload(upload_id)


@router.post("/{upload_id}/normalize")
async def normalize_upload(
    upload_id: str,
    normalizer: EventNormalizationServiceDep,
):
    return await normalizer.normalize_upload(upload_id)


@router.post("/{upload_id}/analyze", response_model=SecurityAnalysisSummaryResponse)
async def analyze_upload(
    upload_id: str,
    orchestrator: SecurityAnalysisOrchestratorDep,
) -> SecurityAnalysisSummaryResponse:
    return await orchestrator.analyze_upload(upload_id)


@router.get("/{upload_id}/analysis", response_model=SecurityAnalysisResponse)
async def get_analysis(
    upload_id: str,
    orchestrator: SecurityAnalysisOrchestratorDep,
) -> SecurityAnalysisResponse:
    return await orchestrator.get_analysis(upload_id)
