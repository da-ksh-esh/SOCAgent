"""Mock ticketing system and mock Slack/email notifier. Nothing leaves the process."""
from __future__ import annotations

from datetime import datetime, timedelta

ON_CALL = ["A. Sharma (L2)", "R. Iyer (L2)", "M. Khan (L1)", "S. Patel (L1)"]
SLA_MINUTES = {"critical": 30, "high": 60, "medium": 240, "low": None}
PRIORITY = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"}


def create_ticket(number: int, incident: dict, now: datetime) -> dict:
    """Create a ticket; low-severity incidents are created already closed."""
    label = incident["label"]
    sla = SLA_MINUTES[label]
    closed = incident["route"] == "auto_close"
    return {
        "ticket_id": f"SOC-{now:%Y}-{number:04d}", "incident_id": incident["id"],
        "title": f"[{PRIORITY[label]}] {incident['headline']}",
        "priority": PRIORITY[label], "severity": incident["severity"], "status": "Closed" if closed else "Open",
        "queue": {"auto_close": "Auto-closed", "analyst_queue": "Analyst queue",
                  "escalate": "Incident response"}[incident["route"]],
        "assignee": "" if closed else ON_CALL[number % len(ON_CALL)],
        "created": now.strftime("%Y-%m-%d %H:%M"),
        "sla_minutes": sla, "sla_due": (now + timedelta(minutes=sla)).strftime("%Y-%m-%d %H:%M") if sla else "",
        "needs_human_review": bool(incident.get("needs_human_review")),
    }


def notify(channel: str, recipient: str, message: str, now: datetime) -> dict:
    """Mock Slack / email notification: recorded, never sent."""
    return {"channel": channel, "to": recipient, "message": message,
            "sent_at": now.strftime("%H:%M:%S"), "delivered": "simulated"}
