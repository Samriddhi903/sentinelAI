"""Global exception handlers for structured API errors."""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.core.exceptions import AppError, ReportNotFoundError


def register_exception_handlers(app: FastAPI) -> None:

    @app.exception_handler(AppError)
    async def handle_app_error(_request: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "detail": exc.detail,
                "code": exc.code
            },
        )

    @app.exception_handler(ReportNotFoundError)
    async def handle_report_not_found(_request: Request, exc: ReportNotFoundError) -> JSONResponse:
        return JSONResponse(
            status_code=200,
            content={
                "status": "processing",
                "error": "report_not_ready"
            },
        )