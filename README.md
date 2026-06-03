# SentinelAI

AI-powered Security Intelligence Platform — final-year placement project.

SentinelAI ingests log files, normalizes events, detects threats, maps findings to MITRE ATT&CK, and generates remediation guidance through a multi-agent workflow.

## Phase 1 — Backend Foundation

Phase 1 delivers the FastAPI application skeleton with centralized configuration, structured logging, MongoDB connectivity (degraded mode), dependency injection, and health endpoints.

### Prerequisites

- Python 3.12+
- MongoDB Atlas account (optional for local dev; readiness reflects connection state)
- Git

### Project Structure

```
SentinelAI/
├── backend/          # FastAPI application
├── samples/          # Demo log files for future phases
└── README.md
```

### Backend Setup

1. Create and activate a virtual environment:

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

2. Copy environment template and configure values:

```powershell
copy .env.example .env
```

3. Run the API:

```powershell
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

4. Open API docs: http://localhost:8000/docs

### Environment Variables (Phase 1)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MONGODB_URI` | No | empty | MongoDB Atlas connection string |
| `MONGODB_DB_NAME` | No | `sentinelai` | Database name |
| `SECRET_KEY` | No | empty | Loaded for future auth phases |
| `LOG_FORMAT` | No | `console` | `console` or `json` |
| `LOG_LEVEL` | No | `INFO` | Logging level |
| `ALLOWED_ORIGINS` | No | `http://localhost:5173` | Comma-separated CORS origins |
| `UPLOAD_DIR` | No | `./uploads` | Upload storage path (Phase 2+) |
| `MAX_UPLOAD_SIZE_MB` | No | `10` | Max upload size (Phase 2+) |

Future phases will also use `GEMINI_API_KEY`.

### Health Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/health/live` | Liveness probe — no database check |
| GET | `/api/v1/health/ready` | Readiness probe — MongoDB ping (200 connected / 503 disconnected) |

### Running Tests

```powershell
cd backend
pytest
```

Tests do not require a live MongoDB instance.

### Code Quality

Install pre-commit hooks from the repository root:

```powershell
pip install pre-commit
pre-commit install
pre-commit run --all-files
```

Configured tools: **ruff**, **black**, **isort**.

### Sample Data

Demo log snippets are in `samples/`:

- `nginx.log`
- `apache.log`
- `syslog.log`
- `sample.json`

These will be used in parser and detection phases.

## License

Academic / placement project.
