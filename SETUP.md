# SentinelAI Setup Guide

This file documents the full setup process for running the SentinelAI project on a new laptop.

## 1. Prerequisites

- Git
- Python 3.12
- Node.js 18+ (Node 20 recommended)
- MongoDB access (local or cloud)
- `npm` package manager

## 2. Verify repository files

Ensure the repository contains:

- `backend/requirements.txt`
- `backend/pyproject.toml`
- `backend/app/`
- `backend/tests/`
- `frontend/package.json`
- `frontend/src/`
- `backend/.env.example`
- `frontend/.env.example`

## 3. Verify sensitive files are ignored

The repository already ignores common secrets and local state:

- `.env`
- `.env.local`
- `.env.*.local`
- `backend/.venv/`
- `uploads/`
- `frontend/node_modules/`

> I verified that `backend/.env` is currently ignored and not tracked by git.

If you ever accidentally track a `.env` file, remove it from git index without deleting the local file:

```bash
cd c:\Users\hp\Documents\projects\SentinelAI
git rm --cached backend/.env
git commit -m "Remove tracked env file"
```

## 4. Backend setup

1. Open a terminal and change to the backend folder:

   ```bash
   cd c:\Users\hp\Documents\projects\SentinelAI\backend
   ```

2. Create a Python virtual environment:

   ```bash
   python -m venv .venv
   ```

3. Activate the virtual environment:

   - PowerShell:
     ```powershell
     .\.venv\Scripts\Activate.ps1
     ```
   - Command Prompt:
     ```cmd
     .\.venv\Scripts\activate.bat
     ```
   - Git Bash / WSL:
     ```bash
     source .venv/bin/activate
     ```

4. Upgrade pip:

   ```bash
   python -m pip install --upgrade pip
   ```

5. Install backend dependencies:

   ```bash
   pip install -r requirements.txt
   ```

6. Create the local backend environment file:

   ```bash
   copy .env.example .env
   ```

7. Edit `backend/.env` and fill in values for:

   - `MONGODB_URI`
   - `GEMINI_API_KEY`
   - `SECRET_KEY`

   Example placeholders:

   ```env
   MONGODB_URI=mongodb://localhost:27017
   MONGODB_DB_NAME=sentinelai
   GEMINI_API_KEY=<your_gemini_api_key>
   SECRET_KEY=<random_secret>
   UPLOAD_DIR=./uploads
   MAX_UPLOAD_SIZE_MB=10
   ALLOWED_ORIGINS=http://localhost:5173
   LOG_FORMAT=console
   LOG_LEVEL=INFO
   ```

8. Ensure the upload directory exists:

   ```bash
   mkdir uploads
   ```

9. Start the backend:

   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```

## 5. Frontend setup

1. Change to the frontend folder:

   ```bash
   cd c:\Users\hp\Documents\projects\SentinelAI\frontend
   ```

2. Install Node dependencies:

   ```bash
   npm install
   ```

3. Create the local frontend environment file:

   ```bash
   copy .env.example .env
   ```

4. Run the frontend app:

   ```bash
   npm run dev
   ```

5. Open the frontend in the browser at:

   - `http://localhost:5173`

## 6. Running backend tests

From the `backend` folder with the virtual environment activated:

```bash
pytest
```

## 7. Dependency review

The following dependency files describe the required packages:

- `backend/requirements.txt` for Python backend dependencies
- `backend/pyproject.toml` for formatting and test tooling
- `frontend/package.json` for frontend dependencies

### Backend dependencies already included

- `fastapi`
- `uvicorn[standard]`
- `python-multipart`
- `pydantic-settings`
- `motor`
- `python-json-logger`
- `python-dotenv`
- `python-magic-bin`
- `aiofiles`
- `httpx`
- `pytest`
- `pytest-asyncio`
- `ruff`
- `black`
- `isort`
- `pre-commit`

### Frontend dependencies already included

- `react`
- `react-dom`
- `react-router-dom`
- `@mui/material`
- `@mui/icons-material`
- `axios`
- `recharts`
- `@emotion/react`
- `@emotion/styled`

## 8. Notes

- Do not commit any real API keys or secrets.
- Keep `.env` files local only.
- Commit `.env.example` instead so new laptops can copy it safely.
- If you need to push to GitHub, commit only source code and example env templates.
