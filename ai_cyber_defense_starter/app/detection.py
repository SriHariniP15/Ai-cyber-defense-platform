from datetime import datetime, timezone

def analyze_event(event: dict) -> dict:
    """
    Starter rule-based detector.
    This is a demonstration, not a production security engine.
    """
    event_type = str(event.get("event_type", "")).lower()
    message = str(event.get("message", "")).lower()
    source_ip = event.get("source_ip", "unknown")
    username = event.get("username", "unknown")

    score = 0
    reasons = []

    if event_type in {"login_failed", "authentication_failure"}:
        score += 35
        reasons.append("Failed authentication event")

    if "multiple failed" in message or "brute force" in message:
        score += 40
        reasons.append("Possible brute-force pattern in message")

    if event_type in {"malware_detected", "endpoint_malware"}:
        score += 70
        reasons.append("Malware-related event")

    if event_type in {"firewall_block", "ids_alert", "ips_alert"}:
        score += 30
        reasons.append("Network security control raised an alert")

    score = min(score, 100)
    if score >= 70:
        severity = "high"
    elif score >= 35:
        severity = "medium"
    else:
        severity = "low"

    return {
        "event_id": event.get("event_id", "unknown"),
        "timestamp": event.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "event_type": event_type or "unknown",
        "source_ip": source_ip,
        "username": username,
        "risk_score": score,
        "severity": severity,
        "reasons": reasons or ["No starter detection rule matched"],
        "recommended_action": (
            "Escalate for analyst review; do not automatically block based on this demo score."
            if severity == "high" else
            "Review related events and monitor for recurrence."
            if severity == "medium" else
            "Log and monitor."
        )
    }
