
from typing import TypedDict, Any
from langgraph.graph import StateGraph, START, END


class SOCState(TypedDict, total=False):
    event: dict[str, Any]
    detection: dict[str, Any]
    investigation: dict[str, Any]
    response: dict[str, Any]
    report: dict[str, Any]


# Agent 1: Monitor incoming security events.
def log_monitoring_agent(state: SOCState) -> dict:
    event = state["event"]

    return {
        "detection": {
            "event_id": event.get("event_id", "unknown"),
            "event_type": event.get("event_type", "unknown"),
            "source_ip": event.get("source_ip", "unknown"),
            "monitoring_status": "Event received"
        }
    }


# Agent 2: Assess the supplied risk information.
def threat_detection_agent(state: SOCState) -> dict:
    event = state["event"]
    event_analysis = event.get("analysis", {})

    # Accept either a direct severity field or nested analysis.
    severity = (
        event_analysis.get("severity")
        or event.get("severity")
        or "low"
    )

    ml_analysis = event_analysis.get("ml_analysis", {})

    return {
        "investigation": {
            "severity": severity,
            "ml_anomaly": ml_analysis.get("is_anomaly", False),
            "reason": (
                "High severity requires investigation"
                if severity == "high"
                else "Review event context and related activity"
            )
        }
    }


# Agent 3: Recommend a response without executing it.
def response_agent(state: SOCState) -> dict:
    investigation = state["investigation"]
    severity = investigation["severity"]

    if severity == "high":
        action = "Escalate to analyst; review containment options"
    elif severity == "medium":
        action = "Investigate related events and monitor"
    else:
        action = "Log event and continue monitoring"

    return {
        "response": {
            "recommended_action": action,
            "automatic_action_taken": False
        }
    }


# Agent 4: Generate an incident summary.
def reporting_agent(state: SOCState) -> dict:
    return {
        "report": {
            "event_id": state["detection"]["event_id"],
            "severity": state["investigation"]["severity"],
            "ml_anomaly": state["investigation"]["ml_anomaly"],
            "recommended_action": state["response"]["recommended_action"],
            "status": "Analysis complete"
        }
    }


# Connect the agents into a directed workflow.
builder = StateGraph(SOCState)

builder.add_node("log_monitoring", log_monitoring_agent)
builder.add_node("threat_detection", threat_detection_agent)
builder.add_node("response", response_agent)
builder.add_node("reporting", reporting_agent)

builder.add_edge(START, "log_monitoring")
builder.add_edge("log_monitoring", "threat_detection")
builder.add_edge("threat_detection", "response")
builder.add_edge("response", "reporting")
builder.add_edge("reporting", END)

soc_workflow = builder.compile()


if __name__ == "__main__":
    sample_event = {
        "event_id": "soc-demo-001",
        "event_type": "login_failed",
        "source_ip": "192.0.2.50",
        "analysis": {
            "severity": "high",
            "ml_analysis": {
                "is_anomaly": True
            }
        }
    }

    result = soc_workflow.invoke({"event": sample_event})

    print("\n=== AI CYBER DEFENSE: WORKFLOW REPORT ===")
    print(result["report"])
