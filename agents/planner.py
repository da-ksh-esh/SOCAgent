"""1 Planner agent: groups raw alerts into candidate incidents and writes the task plan.

Decision: alerts on the same host that arrive within WINDOW_MIN of each other belong to the
same candidate incident. Each candidate gets the same ordered task list for the other agents.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta

from core.state import SOCState
from core.trace import Tracer

WINDOW_MIN = 30
REQUIRED_FIELDS = ["id", "ts", "source", "host", "rule_name"]
TASKS = ["enrich (Research)", "correlate + score (Executor)", "validate (Critic 1)",
         "route by severity", "respond (Software Dev, if high)", "ticket + report (Business Automation)"]


def parse_alerts(alerts: list[dict]) -> list[dict]:
    """Drop malformed alerts and sort by time."""
    valid = [a for a in alerts if all(a.get(f) for f in REQUIRED_FIELDS)]
    return sorted(valid, key=lambda a: a["ts"])


def group_alerts(alerts: list[dict], window_min: int = WINDOW_MIN) -> list[list[dict]]:
    """Split each host's alert stream wherever the gap exceeds the window."""
    gap = timedelta(minutes=window_min)
    groups: list[list[dict]] = []
    for a in sorted(alerts, key=lambda a: (a["host"], a["ts"])):
        last = groups[-1][-1] if groups else None
        if (last and last["host"] == a["host"]
                and datetime.fromisoformat(a["ts"]) - datetime.fromisoformat(last["ts"]) <= gap):
            groups[-1].append(a)
        else:
            groups.append([a])
    return sorted(groups, key=lambda g: g[0]["ts"])


def planner_node(state: SOCState) -> dict:
    t = Tracer("Planner")
    window = state["config"].get("window_min", WINDOW_MIN)
    alerts = t.call("alert_parser", parse_alerts, state["alerts"], action="parse and validate alerts",
                    inputs=f"{len(state['alerts'])} raw alerts",
                    show=lambda r: dict(Counter(a["source"] for a in r)))
    groups = t.call("group_by_host_window", group_alerts, alerts, window,
                    action=f"group alerts by host within {window}-min windows",
                    inputs=f"{len(alerts)} alerts, window={window}m",
                    show=lambda g: f"{len(g)} candidate incidents")

    plan = []
    for n, group in enumerate(groups, start=1):
        candidate = {
            "candidate_id": f"INC-{n:03d}", "host": group[0]["host"],
            "users": sorted({a["user"] for a in group if a["user"]}),
            "alert_ids": [a["id"] for a in group], "window": [group[0]["ts"], group[-1]["ts"]],
            "tasks": TASKS,
        }
        plan.append(candidate)
        t.log("queue task plan", "task_queue.push", candidate["candidate_id"],
              f"{group[0]['host']}: {len(group)} alert(s), {len(TASKS)} tasks")
    t.log("plan complete", "", f"{len(alerts)} alerts", f"{len(plan)} candidate incidents queued")
    return {"task_plan": plan, "trace": t.entries}
