"""Shared workflow state. Every agent reads it and returns a partial update.

`trace` and `critic_verdicts` are append-only: LangGraph concatenates what each node returns.
All other keys are overwritten by the node that writes them.
"""
from __future__ import annotations

import operator
from typing import Annotated, Any, TypedDict


class SOCState(TypedDict, total=False):
    config: dict[str, Any]                 # data_dir, mode, fault injection settings
    alerts: list[dict]
    task_plan: list[dict]                  # Planner: one entry per candidate incident
    enriched_context: dict[str, Any]       # Research: per-alert intel/behaviour, hosts, users
    incidents: list[dict]                  # Executor (Router adds route + notes)
    severity: dict[str, int]               # Executor: incident id -> score
    critic_verdicts: Annotated[list[dict], operator.add]
    prose_checks: Annotated[list[dict], operator.add]   # Critic fact-checks of LLM-written text
    retries: dict[str, int]                # {"cp1": n, "cp2": n}
    checkpoint_status: dict[str, str]      # {"cp1": "pass" | "retry" | "flagged", "cp1_target": ...}
    detection_rule: dict[str, dict]        # Software Development: incident id -> rule bundle
    playbook: dict[str, list[dict]]        # Software Development: incident id -> ordered steps
    approvals: dict[str, dict]             # Analyst: incident id -> containment decision
    ticket: dict[str, dict]                # Business Automation: incident id -> ticket
    notifications: list[dict]
    report: dict[str, Any]                 # Business Automation: summary, handover, per-incident
    trace: Annotated[list[dict], operator.add]


def initial_state(alerts: list[dict], config: dict[str, Any]) -> SOCState:
    return {
        "config": config, "alerts": alerts, "task_plan": [], "enriched_context": {},
        "incidents": [], "severity": {}, "critic_verdicts": [], "prose_checks": [], "retries": {"cp1": 0, "cp2": 0},
        "checkpoint_status": {}, "detection_rule": {}, "playbook": {}, "approvals": {}, "ticket": {},
        "notifications": [], "report": {}, "trace": [],
    }
