# AI Cyber Defense Platform — Starter MVP

This first milestone implements a small FastAPI backend for ingesting demo security events, applying transparent starter rules, saving events locally, and listing alerts.

## Requirements
- Python 3.10+
- pip

## Setup (Windows PowerShell)
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

If PowerShell blocks activation, use:
```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000/docs to test the API interactively.

## Endpoints
- `GET /` — API welcome message
- `GET /health` — health check
- `POST /events` — ingest one event, score it, and save it
- `GET /events` — list stored events
- `GET /alerts` — list medium/high alerts
- `GET /alerts?severity=high` — list high-severity alerts
- `GET /summary` — counts by severity

## Example POST body
```json
{
  "event_id": "evt-003",
  "source": "demo-auth",
  "event_type": "login_failed",
  "source_ip": "192.0.2.10",
  "username": "demo_user",
  "message": "User authentication failed"
}
```

## Current limitations
- Uses transparent demonstration rules, not a trained ML model.
- Stores data in a local JSON file, not PostgreSQL.
- No automatic blocking or other real-world response actions.
- Do not upload real credentials, personal data, or sensitive production logs.
- A single event does not prove an attack; scores are triage hints for a student demo.

## Next milestones
1. Add repeated-failure correlation across events.
2. Add tests and stronger event normalization.
3. Replace JSON storage with PostgreSQL.
4. Add a baseline anomaly-detection model.
5. Add LangGraph agents and human-approved response recommendations.
6. Add React dashboard and alerts.
