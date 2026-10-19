"""Human-in-the-loop checkpoint: an analyst decides containment for each high-severity incident.

The graph pauses here with LangGraph's interrupt() and resumes with the analyst's decisions:
  approved        containment authorised; the incident's bad indicators are block-listed in memory
  rejected        containment put on hold; nothing learned
  false_positive  containment cancelled; indicators allow-listed and user baselines widened in memory
No containment step is treated as authorised until a human approves it. With approval switched
off (headless benchmark, tests) every decision is recorded as auto-approved and nothing is learned.
"""
from __future__ import annotations

from langgraph.types import interrupt

from core import memory
from core.state import SOCState
from core.trace import Tracer


def approval_request(state: SOCState) -> list[dict]:
    """What the analyst sees for each escalated incident."""
    request = []
    for inc in [i for i in state["incidents"] if i["route"] == "escalate"]:
        final_cp2 = [v for v in state["critic_verdicts"] if v["checkpoint"] == 2 and v["incident_id"] == inc["id"]]
        request.append({
            "incident_id": inc["id"], "headline": inc["headline"], "severity": inc["severity"],
            "label": inc["label"], "needs_human_review": bool(inc.get("needs_human_review")),
            "containment": [s["action"] for s in state["playbook"].get(inc["id"], []) if s["phase"] == "contain"],
            "critic_passed": bool(final_cp2 and final_cp2[-1]["passed"]),
        })
    return request


def approval_node(state: SOCState) -> dict:
    t = Tracer("Analyst (human)")
    cfg = state["config"]
    request = approval_request(state)
    if not cfg.get("require_approval"):
        decisions = {r["incident_id"]: {"decision": "approved", "by": "auto (approval disabled)", "comment": ""}
                     for r in request}
    else:
        # Pauses the graph; the UI resumes it with {incident_id: {"decision", "by", "comment"}}.
        decisions = interrupt({"type": "containment_approval", "incidents": request})
    by_id = {i["id"]: i for i in state["incidents"]}
    alerts_by_id = {a["id"]: a for a in state["alerts"]}
    for incident_id, d in decisions.items():
        t.log(f"containment {d['decision'].replace('_', ' ')}", "analyst_console", incident_id,
              f"by {d['by']}" + (f": {d['comment']}" if d.get("comment") else ""),
              status="pass" if d["decision"] == "approved" else "fail")
        verdict = {"approved": "confirmed", "false_positive": "false_positive"}.get(d["decision"])
        if verdict and cfg.get("use_memory") and cfg.get("require_approval"):
            inc = by_id[incident_id]
            learned = t.call("memory.learn", memory.learn, inc, [alerts_by_id[a] for a in inc["alert_ids"]],
                             state["enriched_context"], verdict, d["by"], action=f"remember analyst verdict ({verdict})",
                             inputs=incident_id, show=lambda r: {k: v for k, v in r.items() if v})
            d["learned"] = learned
    return {"approvals": decisions, "trace": t.entries}
