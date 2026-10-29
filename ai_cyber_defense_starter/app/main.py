import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.detection import analyze_event
from datetime import datetime, timedelta, timezone
from app.ml_detector import detect_anomaly
from app.agent_workflow import soc_workflow
app = FastAPI(
    title="AI Cyber Defense Platform",
    description="Student-level SOC prototype: ingest, normalize, and score security events.",
    version="0.1.0",
)

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "events.json"


class SecurityEvent(BaseModel):
    event_id: str
    timestamp: str | None = None
    source: str = "demo"
    event_type: str
    source_ip: str | None = None
    username: str | None = None
    message: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


def load_events() -> list[dict]:
    if not DATA_FILE.exists():
        return []
    try:
        return json.loads(DATA_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []


def save_events(events: list[dict]) -> None:
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    DATA_FILE.write_text(json.dumps(events, indent=2), encoding="utf-8")


@app.get("/")
def home():
    return {
        "message": "AI Cyber Defense Platform API is running",
        "docs": "/docs",
        "next_step": "POST a security event to /events"
    }


@app.get("/health")
def health():
    return {"status": "ok"}



@app.post("/events")
def ingest_event(event: SecurityEvent):
    """Ingest, score, and correlate security events."""
    normalized = event.model_dump()
    normalized["source_ip"] = normalized.get("source_ip") or "unknown"
    normalized["username"] = normalized.get("username") or "unknown"

    # Use a consistent timestamp for correlation.
    current_time = datetime.now(timezone.utc)
    if normalized.get("timestamp"):
        current_time = datetime.fromisoformat(
            normalized["timestamp"].replace("Z", "+00:00")
        )
        if current_time.tzinfo is None:
            current_time = current_time.replace(tzinfo=timezone.utc)

    normalized["timestamp"] = current_time.isoformat()

    # Load previously recorded events.
    events = load_events()

    # Apply the existing detection rules.
    result = analyze_event(normalized)

    # Detect repeated failed logins from the same IP
    # within the previous five minutes.
    is_failed_login = normalized["event_type"].lower() in {
        "login_failed",
        "authentication_failure",
    }

    if is_failed_login and normalized["source_ip"] != "unknown":
        failed_attempts = 1  # Include the current event.
        window_start = current_time - timedelta(minutes=5)

        for previous in events:
            previous_type = previous.get("event_type", "").lower()
            previous_ip = previous.get("source_ip", "unknown")

            if previous_type not in {
                "login_failed",
                "authentication_failure",
            }:
                continue

            if previous_ip != normalized["source_ip"]:
                continue

            previous_time = (
                previous.get("timestamp")
                or previous.get("analysis", {}).get("timestamp")
            )

            if not previous_time:
                continue

            try:
                parsed_time = datetime.fromisoformat(
                    previous_time.replace("Z", "+00:00")
                )

                if parsed_time.tzinfo is None:
                    parsed_time = parsed_time.replace(
                        tzinfo=timezone.utc
                    )

                if window_start <= parsed_time <= current_time:
                    failed_attempts += 1

            except (ValueError, TypeError):
                continue

        # Five or more failed attempts trigger a high-severity alert.
        if failed_attempts >= 5:
            result["risk_score"] = 85
            result["severity"] = "high"
            result["reasons"].append(
                f"Possible brute-force activity: "
                f"{failed_attempts} failed logins from the same IP "
                f"within five minutes"
            )
            result["recommended_action"] = (
                "Escalate for analyst review and investigate the "
                "source IP. No automatic blocking is performed."
            )
    
    # Run ML anomaly detection using event metadata.
    metadata = normalized.get("metadata") or {}
    event_type = normalized.get("event_type", "").lower()

    ml_result = detect_anomaly(
        failed_logins=int(
            metadata.get(
                "failed_logins",
                1 if event_type in {
                    "login_failed",
                    "authentication_failure"
                } else 0
            )
        ),
        requests_per_minute=int(
            metadata.get("requests_per_minute", 10)
        ),
        unusual_port=int(metadata.get("unusual_port", 0)),
        malware_alert=int(
            metadata.get(
                "malware_alert",
                1 if event_type in {
                    "malware_detected",
                    "endpoint_malware"
                } else 0
            )
        )
    )

    # Keep ML output separate from the rule-based assessment.
    result["ml_analysis"] = ml_result

        # Run the LangGraph multi-agent workflow.
    workflow_input = {
        **normalized,
        "analysis": result
    }

    workflow_result = soc_workflow.invoke({
        "event": workflow_input
    })

    # Attach the generated incident report.
    result["agent_report"] = workflow_result["report"]

    


    # Save the event and its analysis.
    record = {**normalized, "analysis": result}
    events.append(record)
    save_events(events)

    return {
        "message": "Event ingested",
        "event": record,
    }



@app.get("/events")
def list_events():
    return {"count": len(load_events()), "events": load_events()}


@app.get("/alerts")
def list_alerts(severity: str | None = None):
    events = load_events()
    alerts = [
        event for event in events
        if event.get("analysis", {}).get("severity") in {"medium", "high"}
    ]
    if severity:
        severity = severity.lower()
        if severity not in {"medium", "high"}:
            raise HTTPException(status_code=400, detail="severity must be medium or high")
        alerts = [
            event for event in alerts
            if event.get("analysis", {}).get("severity") == severity
        ]
    return {"count": len(alerts), "alerts": alerts}


@app.get("/summary")
def summary():
    events = load_events()
    counts = {"low": 0, "medium": 0, "high": 0}
    for event in events:
        level = event.get("analysis", {}).get("severity", "low")
        counts[level] = counts.get(level, 0) + 1
    return {"total_events": len(events), "severity_counts": counts}
