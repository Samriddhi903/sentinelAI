"""FastAPI application factory and lifespan management."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.routes.anomaly import router as anomaly_router
from app.api.v1.routes.features import router as features_router
from app.api.v1.routes.health import router as health_router
from app.api.v1.routes.report import router as report_router
from app.api.v1.routes.upload import router as upload_router
from app.core.config import get_settings
from app.core.exception_handlers import register_exception_handlers
from app.core.logging import configure_logging, get_logger
from app.database.connection import get_database_manager
from app.repositories.detection_repository import DetectionRepository
from app.repositories.investigation_repository import InvestigationRepository
from app.repositories.risk_assessment_repository import RiskAssessmentRepository
from app.repositories.upload_repository import UploadRepository
from app.services.file_storage_service import FileStorageService

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    settings = get_settings()
    configure_logging(settings.log_format, settings.log_level)
    db_manager = get_database_manager()

    logger.info(
        "Starting SentinelAI application",
        extra={"version": settings.app_version, "log_format": settings.log_format},
    )

    await db_manager.connect(settings.mongodb_uri, settings.mongodb_db_name)

    if db_manager.database is not None:
        upload_repository = UploadRepository(db_manager.database)
        from app.repositories.event_repository import EventRepository
        from app.repositories.feature_repository import FeatureRepository

        await upload_repository.ensure_indexes()
        # ensure other collections also have indexes
        event_repository = EventRepository(db_manager.database)
        await event_repository.ensure_indexes()
        feature_repository = FeatureRepository(db_manager.database)
        await feature_repository.ensure_indexes()
        from app.repositories.anomaly_repository import AnomalyRepository
        from app.repositories.report_repository import ReportRepository

        report_repository = ReportRepository(db_manager.database)
        await report_repository.ensure_indexes()

        anomaly_repository = AnomalyRepository(db_manager.database)
        await anomaly_repository.ensure_indexes()

        detection_repository = DetectionRepository(db_manager.database)
        await detection_repository.ensure_indexes()
        risk_repository = RiskAssessmentRepository(db_manager.database)
        await risk_repository.ensure_indexes()
        investigation_repository = InvestigationRepository(db_manager.database)
        await investigation_repository.ensure_indexes()

        file_storage = FileStorageService(settings)
        file_storage.ensure_upload_dir()

    yield
    await db_manager.disconnect()
    logger.info("SentinelAI application shutdown complete")


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    register_exception_handlers(app)

    app.include_router(health_router, prefix="/api/v1")
    app.include_router(upload_router, prefix="/api/v1")
    app.include_router(features_router, prefix="/api/v1")
    app.include_router(report_router, prefix="/api/v1")
    app.include_router(anomaly_router, prefix="/api/v1")

    return app
