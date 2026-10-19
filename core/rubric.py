"""Severity rubric: the single source of truth for scoring and routing.

severity = min(100, stage_points + asset_points + intel_points + behaviour_points), floored at 0.
Both the Executor and the Critic score through this module, but each computes its own inputs.
"""
from __future__ import annotations

POINTS_PER_STAGE = 15
MAX_STAGE_POINTS = 45
ASSET_POINTS = {"low": 0, "medium": 10, "high": 20, "crown_jewel": 25}
INTEL_POINTS = {"malicious": 20, "suspicious": 10, "unknown": 0, "benign": -10}
BEHAVIOUR_POINTS = {"anomalous": 10, "normal": 0}

LOW_THRESHOLD = 40       # below this: auto-close
HIGH_THRESHOLD = 70      # at or above this: playbook + detection rule
CRITICAL_THRESHOLD = 90  # label only (tighter SLA), same route as high
MAX_RETRIES = 2          # Critic send-backs per checkpoint before flagging for a human


def compute_severity(stage_count: int, asset: str, intel: str, behaviour: str) -> dict:
    """Return each rubric component and the clamped total."""
    parts = {
        "stage_points": min(MAX_STAGE_POINTS, POINTS_PER_STAGE * stage_count),
        "asset_points": ASSET_POINTS.get(asset, 0),
        "intel_points": INTEL_POINTS.get(intel, 0),
        "behaviour_points": BEHAVIOUR_POINTS.get(behaviour, 0),
    }
    parts["total"] = max(0, min(100, sum(parts.values())))
    return parts


def band(score: int) -> str:
    """low (<40), medium (40-69) or high (>=70)."""
    if score < LOW_THRESHOLD:
        return "low"
    if score < HIGH_THRESHOLD:
        return "medium"
    return "high"


def label(score: int) -> str:
    """Display label; 'critical' is a high-band incident scoring 90+."""
    return "critical" if score >= CRITICAL_THRESHOLD else band(score)


ROUTES = {"low": "auto_close", "medium": "analyst_queue", "high": "escalate"}


def route_for(score: int) -> str:
    return ROUTES[band(score)]
