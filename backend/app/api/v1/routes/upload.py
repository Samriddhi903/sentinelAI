"""Upload API routes."""

from fastapi import APIRouter, File, UploadFile

from app.dependencies import UploadServiceDep
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
