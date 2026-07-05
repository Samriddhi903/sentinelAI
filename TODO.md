# TODO: ML anomaly detection layer (Isolation Forest)

- [ ] Explore and confirm feature document schema in Mongo features collection
- [ ] Implement `app/services/anomaly_detection_service.py`
- [ ] Add `app/schemas/anomaly.py`
- [ ] Add `app/repositories/anomaly_repository.py`
- [ ] Integrate ML into `SecurityAnalysisOrchestrator` to return `anomaly_detection`
- [ ] Add API endpoint `GET /api/v1/upload/{upload_id}/anomaly`
- [ ] Wire DI dependencies for new service/repo
- [ ] Add tests: feature vector creation, scoring+normalization, low-sample fallback, persistence, endpoint, integration
- [ ] Add dependencies: numpy, scikit-learn
- [ ] Run backend tests

