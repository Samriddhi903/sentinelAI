"""Security report generation API routes."""

from fastapi import APIRouter

from app.dependencies import ReportGenerationServiceDep
from app.schemas.report import ReportGenerateResponse, SecurityReportSchema

router = APIRouter(prefix="/upload", tags=["reports"])


@router.post("/{upload_id}/report", response_model=ReportGenerateResponse)
async def generate_report(
    upload_id: str,
    service: ReportGenerationServiceDep,
) -> ReportGenerateResponse:
    return await service.generate_report(upload_id)


@router.get("/{upload_id}/report", response_model=SecurityReportSchema)
async def get_report(
    upload_id: str,
    service: ReportGenerationServiceDep,
) -> SecurityReportSchema:
    return await service.get_report(upload_id)
