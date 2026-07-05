"""FastAPI dependency injection providers."""

from typing import Annotated

from fastapi import Depends

from app.core.config import Settings, get_settings
from app.core.exceptions import DatabaseUnavailableError
from app.database.connection import DatabaseManager, get_database_manager
from app.repositories.upload_repository import UploadRepository
from app.services.file_storage_service import FileStorageService
from app.services.health_service import HealthService
from app.services.upload_service import UploadService
from app.services.upload_validator import UploadValidator
from app.services.format_detection_service import FormatDetectionService
from app.parsers.registry import ParserRegistry
from app.parsers.nginx_parser import NginxParser
from app.parsers.apache_parser import ApacheParser
from app.parsers.syslog_parser import SyslogParser
from app.parsers.json_log_parser import JsonLogParser
from app.repositories.event_repository import EventRepository
from app.services.event_normalization_service import EventNormalizationService
from app.repositories.feature_repository import FeatureRepository
from app.repositories.detection_repository import DetectionRepository
from app.repositories.risk_assessment_repository import RiskAssessmentRepository
from app.repositories.investigation_repository import InvestigationRepository
from app.repositories.report_repository import ReportRepository
from app.services.feature_engineering_service import FeatureEngineeringService
from app.services.detection_engine import DetectionEngine
from app.services.mitre_mapper import MitreMapper
from app.services.risk_scoring_engine import RiskScoringEngine
from app.services.timeline_builder import TimelineBuilder
from app.services.investigation_service import InvestigationService
from app.services.security_analysis_orchestrator import SecurityAnalysisOrchestrator
from app.services.gemini_service import GeminiService
from app.services.report_generation_service import ReportGenerationService
from app.services.anomaly_detection_service import AnomalyDetectionService
from app.repositories.anomaly_repository import AnomalyRepository


SettingsDep = Annotated[Settings, Depends(get_settings)]
DatabaseManagerDep = Annotated[DatabaseManager, Depends(get_database_manager)]


def get_health_service(
    settings: SettingsDep,
    db_manager: DatabaseManagerDep,
) -> HealthService:
    return HealthService(settings=settings, db_manager=db_manager)


HealthServiceDep = Annotated[HealthService, Depends(get_health_service)]


def get_upload_repository(db_manager: DatabaseManagerDep) -> UploadRepository:
    if db_manager.database is None:
        raise DatabaseUnavailableError()
    return UploadRepository(db_manager.database)


UploadRepositoryDep = Annotated[UploadRepository, Depends(get_upload_repository)]


def get_file_storage_service(settings: SettingsDep) -> FileStorageService:
    return FileStorageService(settings)


FileStorageServiceDep = Annotated[FileStorageService, Depends(get_file_storage_service)]


def get_upload_validator(settings: SettingsDep) -> UploadValidator:
    return UploadValidator(settings)


UploadValidatorDep = Annotated[UploadValidator, Depends(get_upload_validator)]


def get_parser_registry() -> ParserRegistry:
    registry = ParserRegistry()
    registry.register_parser(NginxParser())
    registry.register_parser(ApacheParser())
    registry.register_parser(SyslogParser())
    registry.register_parser(JsonLogParser())
    return registry


ParserRegistryDep = Annotated[ParserRegistry, Depends(get_parser_registry)]


def get_upload_service(
    db_manager: DatabaseManagerDep,
    upload_repository: UploadRepositoryDep,
    file_storage: FileStorageServiceDep,
    upload_validator: UploadValidatorDep,
    parser_registry: ParserRegistryDep,
) -> UploadService:
    detection_service = FormatDetectionService(parser_registry)

    return UploadService(
        db_manager=db_manager,
        upload_repository=upload_repository,
        file_storage=file_storage,
        upload_validator=upload_validator,
        format_detection_service=detection_service,
    )


UploadServiceDep = Annotated[UploadService, Depends(get_upload_service)]


def get_event_repository(db_manager: DatabaseManagerDep) -> EventRepository:
    if db_manager.database is None:
        raise DatabaseUnavailableError()
    return EventRepository(db_manager.database)


EventRepositoryDep = Annotated[EventRepository, Depends(get_event_repository)]


def get_event_normalization_service(
    upload_repository: UploadRepositoryDep,
    event_repository: EventRepositoryDep,
    file_storage: FileStorageServiceDep,
    parser_registry: ParserRegistryDep,
) -> EventNormalizationService:
    return EventNormalizationService(
        upload_repository=upload_repository,
        event_repository=event_repository,
        file_storage=file_storage,
        parser_registry=parser_registry,
    )


EventNormalizationServiceDep = Annotated[EventNormalizationService, Depends(get_event_normalization_service)]


def get_feature_repository(db_manager: DatabaseManagerDep) -> FeatureRepository:
    if db_manager.database is None:
        raise DatabaseUnavailableError()
    return FeatureRepository(db_manager.database)


FeatureRepositoryDep = Annotated[FeatureRepository, Depends(get_feature_repository)]


def get_detection_repository(db_manager: DatabaseManagerDep) -> DetectionRepository:
    if db_manager.database is None:
        raise DatabaseUnavailableError()
    return DetectionRepository(db_manager.database)


DetectionRepositoryDep = Annotated[DetectionRepository, Depends(get_detection_repository)]


def get_risk_assessment_repository(db_manager: DatabaseManagerDep) -> RiskAssessmentRepository:
    if db_manager.database is None:
        raise DatabaseUnavailableError()
    return RiskAssessmentRepository(db_manager.database)


RiskAssessmentRepositoryDep = Annotated[RiskAssessmentRepository, Depends(get_risk_assessment_repository)]


def get_investigation_repository(db_manager: DatabaseManagerDep) -> InvestigationRepository:
    if db_manager.database is None:
        raise DatabaseUnavailableError()
    return InvestigationRepository(db_manager.database)


InvestigationRepositoryDep = Annotated[InvestigationRepository, Depends(get_investigation_repository)]


def get_report_repository(db_manager: DatabaseManagerDep) -> ReportRepository:
    if db_manager.database is None:
        raise DatabaseUnavailableError()
    return ReportRepository(db_manager.database)


ReportRepositoryDep = Annotated[ReportRepository, Depends(get_report_repository)]


def get_detection_engine() -> DetectionEngine:
    return DetectionEngine()


DetectionEngineDep = Annotated[DetectionEngine, Depends(get_detection_engine)]


def get_mitre_mapper() -> MitreMapper:
    return MitreMapper()


MitreMapperDep = Annotated[MitreMapper, Depends(get_mitre_mapper)]


def get_risk_scoring_engine() -> RiskScoringEngine:
    return RiskScoringEngine()


RiskScoringEngineDep = Annotated[RiskScoringEngine, Depends(get_risk_scoring_engine)]


def get_timeline_builder() -> TimelineBuilder:
    return TimelineBuilder()


TimelineBuilderDep = Annotated[TimelineBuilder, Depends(get_timeline_builder)]


def get_investigation_service(
    repository: InvestigationRepositoryDep,
    risk_engine: RiskScoringEngineDep,
    timeline_builder: TimelineBuilderDep,
    mitre_mapper: MitreMapperDep,
) -> InvestigationService:
    return InvestigationService(
        repository=repository,
        risk_engine=risk_engine,
        timeline_builder=timeline_builder,
        mitre_mapper=mitre_mapper,
    )


InvestigationServiceDep = Annotated[InvestigationService, Depends(get_investigation_service)]


def get_security_analysis_orchestrator(
    upload_repository: UploadRepositoryDep,
    feature_repository: FeatureRepositoryDep,
    detection_repository: DetectionRepositoryDep,
    risk_repository: RiskAssessmentRepositoryDep,
    investigation_repository: InvestigationRepositoryDep,
    detection_engine: DetectionEngineDep,
    mitre_mapper: MitreMapperDep,
    risk_engine: RiskScoringEngineDep,
    timeline_builder: TimelineBuilderDep,
    investigation_service: InvestigationServiceDep,
    anomaly_detection_service: AnomalyDetectionServiceDep,
) -> SecurityAnalysisOrchestrator:
    return SecurityAnalysisOrchestrator(
        upload_repository=upload_repository,
        feature_repository=feature_repository,
        detection_repository=detection_repository,
        risk_repository=risk_repository,
        investigation_repository=investigation_repository,
        detection_engine=detection_engine,
        mitre_mapper=mitre_mapper,
        risk_engine=risk_engine,
        timeline_builder=timeline_builder,
        investigation_service=investigation_service,
        anomaly_detection_service=anomaly_detection_service,
    )



SecurityAnalysisOrchestratorDep = Annotated[SecurityAnalysisOrchestrator, Depends(get_security_analysis_orchestrator)]


def get_gemini_service(settings: SettingsDep) -> GeminiService:
    return GeminiService(api_key=settings.gemini_api_key)


GeminiServiceDep = Annotated[GeminiService, Depends(get_gemini_service)]


def get_report_generation_service(
    upload_repository: UploadRepositoryDep,
    report_repository: ReportRepositoryDep,
    analysis_orchestrator: SecurityAnalysisOrchestratorDep,
    gemini_service: GeminiServiceDep,
) -> ReportGenerationService:
    return ReportGenerationService(
        upload_repository=upload_repository,
        report_repository=report_repository,
        analysis_orchestrator=analysis_orchestrator,
        gemini_service=gemini_service,
    )


ReportGenerationServiceDep = Annotated[ReportGenerationService, Depends(get_report_generation_service)]


def get_feature_engineering_service(
    upload_repository: UploadRepositoryDep,
    event_repository: EventRepositoryDep,
    feature_repository: FeatureRepositoryDep,
) -> FeatureEngineeringService:
    return FeatureEngineeringService(
        upload_repository=upload_repository,
        event_repository=event_repository,
        feature_repository=feature_repository,
    )


FeatureEngineeringServiceDep = Annotated[FeatureEngineeringService, Depends(get_feature_engineering_service)]


def get_anomaly_repository(db_manager: DatabaseManagerDep) -> AnomalyRepository:
    if db_manager.database is None:
        raise DatabaseUnavailableError()
    return AnomalyRepository(db_manager.database)


AnomalyRepositoryDep = Annotated[AnomalyRepository, Depends(get_anomaly_repository)]


def get_anomaly_detection_service(
    feature_repository: FeatureRepositoryDep,
    anomaly_repository: AnomalyRepositoryDep,
) -> AnomalyDetectionService:
    return AnomalyDetectionService(
        feature_repository=feature_repository,
        anomaly_repository=anomaly_repository,
    )


AnomalyDetectionServiceDep = Annotated[
    AnomalyDetectionService, Depends(get_anomaly_detection_service)
]

