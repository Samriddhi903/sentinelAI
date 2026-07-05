from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.dependencies import ReportGenerationServiceDep
from app.schemas.report import ReportGenerateResponse, SecurityReportSchema
from app.core.exceptions import ReportNotFoundError

router = APIRouter(prefix="/upload", tags=["reports"])


@router.post("/{upload_id}/report", response_model=ReportGenerateResponse)
async def generate_report(upload_id: str, service: ReportGenerationServiceDep):
    return await service.generate_report(upload_id)


@router.get("/{upload_id}/report")
async def get_report(upload_id: str, service: ReportGenerationServiceDep):
    try:
        return await service.get_report(upload_id)
    except ReportNotFoundError:
        return JSONResponse(
            status_code=200,
            content={
                "status": "processing",
                "error": "report_not_ready"
            },
        )