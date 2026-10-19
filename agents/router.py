"""Severity router (part of the orchestration layer).

Decision: < 40 auto-close with a justification note, 40-69 analyst queue with a checklist,
>= 70 escalate to the Software Development agent. Incidents the Critic flagged never auto-close.
"""
from __future__ import annotations

from core import rubric
from core.llm import get_llm
from core.state import SOCState
from core.trace import Tracer

CHECKLIST = {
    "credential_access": "Check whether the failing account was locked out and who owns it",
    "initial_access": "Confirm the successful login with the account owner",
    "exfiltration": "Ask the data owner whether the transfer was approved; check destination ownership",
    "execution": "Detonate or reputation-check the downloaded file",
    "reconnaissance": "Confirm the scan matches the scheduled scanner window",
    "command_and_control": "Check proxy logs for other hosts contacting the same domain",
    "delivery": "Pull the phishing email and check other recipients",
    "impact": "Check backup integrity and the scope of encrypted shares",
}


def close_reason(inc: dict) -> str:
    if inc["intel_verdict"] == "benign":
        return "all known indicators are allow-listed (benign threat intel)"
    if not inc["stages"]:
        return "no kill-chain stage matched (" + ", ".join(inc["rule_names"]) + ")"
    return (f"only {', '.join(inc['stages'])} on a {inc['asset_criticality']} asset "
            f"with {inc['behaviour']} user behaviour")


def router_node(state: SOCState) -> dict:
    t = Tracer("Severity router")
    llm = get_llm(state["config"])
    routed = []
    for inc in state["incidents"]:
        inc = dict(inc)
        route = rubric.route_for(inc["severity"])
        if inc.get("needs_human_review") and route == "auto_close":
            route = "analyst_queue"
        inc["route"] = route
        what = ", ".join(s.replace("_", " ") for s in inc["stages"]) or "benign activity"
        inc["headline"] = f"{what[0].upper()}{what[1:]} on {inc['host']}"
        if route == "auto_close":
            inc["close_note"] = llm.write("auto_close_note", {"id": inc["id"], "severity": inc["severity"],
                                                              "reason": close_reason(inc),
                                                              "alert_ids": inc["alert_ids"]})
        elif route == "analyst_queue":
            inc["checklist"] = [CHECKLIST[s] for s in inc["stages"] if s in CHECKLIST] + [
                f"Review cited alerts {', '.join(inc['alert_ids'][:3])} and decide close or escalate"]
        if route != "auto_close":
            t.log("route incident", "severity_router", f"{inc['id']} score {inc['severity']}",
                  {"analyst_queue": "analyst queue (ticket + checklist)",
                   "escalate": "escalate -> Software Development agent"}[route])
        routed.append(inc)
    counts = {r: sum(1 for i in routed if i["route"] == r) for r in ("auto_close", "analyst_queue", "escalate")}
    t.log("routing complete", "", f"{len(routed)} incidents", counts)
    return {"incidents": routed, "trace": t.entries}
