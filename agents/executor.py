"""3 Executor agent: links candidates across hosts, correlates them into incidents and scores severity.

Decision: candidates are merged when one host's activity comes from another candidate's host for
the same user (lateral movement); kill-chain stages come from fixed correlation rules; severity
comes from the rubric. Every claim cites the alert IDs that support it so the Critic can check them.
The LLM only writes the summary, and the Critic fact-checks that summary.
"""
from __future__ import annotations

from core import faults, rubric
from core.llm import get_llm
from core.state import SOCState
from core.trace import Tracer
from agents.critic import enforced, grounded_write
from tools.correlate import KILL_CHAIN, correlate, link_candidates, score_severity


def apply_score(inc: dict, parts: dict, attempt: int) -> None:
    inc.update(severity=parts["total"], score_breakdown=parts, band=rubric.band(parts["total"]),
               label=rubric.label(parts["total"]), attempt=attempt)


def inject_executor_faults(incidents: list[dict], cfg: dict, attempt: int, t: Tracer) -> None:
    """Deliberately wrong work for the fault demo / ablation (see core/faults.py)."""
    ranked = sorted([i for i in incidents if i["band"] != "low"], key=lambda i: -i["severity"]) or incidents

    def target(f):
        return ranked[min(f["pick"], len(ranked) - 1)]

    f = faults.active(cfg, "drop_evidence", attempt)
    if f:
        inc = target(f)
        claim = next((c for c in inc["claims"] if c["kind"] == "stage"), None)
        if claim:
            n, claim["alert_ids"] = len(claim["alert_ids"]), []
            t.log("FAULT: dropped evidence from a claim", "fault_injector", inc["id"],
                  f"claim '{claim['text']}' no longer cites {n} alert IDs", status="fault")
    f = faults.active(cfg, "inflate_score", attempt)
    if f:
        inc = target(f)
        parts = {**inc["score_breakdown"], "total": min(100, inc["severity"] + 20)}
        apply_score(inc, parts, attempt)
        t.log("FAULT: inflated severity without evidence", "fault_injector", inc["id"], f"now {inc['severity']}", status="fault")
    f = faults.active(cfg, "fake_stage", attempt)
    if f:
        inc = target(f)
        stage = next(s for s in KILL_CHAIN if s not in inc["stages"] and s != "reconnaissance")
        inc["stages"].append(stage)
        inc["claims"].insert(0, {"kind": "stage", "stage": stage, "alert_ids": [inc["alert_ids"][0]],
                                 "text": f"{stage.replace('_', ' ').capitalize()}: (unsupported claim)"})
        apply_score(inc, score_severity(inc), attempt)
        t.log("FAULT: claimed an unsupported kill-chain stage", "fault_injector", inc["id"], stage, status="fault")


def executor_node(state: SOCState) -> dict:
    t = Tracer("Executor")
    cfg = state["config"]
    attempt = state["retries"]["cp1"] + 1
    llm = get_llm(cfg)
    if attempt > 1:
        last = [v for v in state["critic_verdicts"] if v["checkpoint"] == 1 and not v["passed"]]
        t.log(f"attempt {attempt}: re-correlating after Critic feedback", "",
              [v["incident_id"] for v in last], "; ".join(r for v in last for r in v["reasons"][:1]))

    alerts_by_id = {a["id"]: a for a in state["alerts"]}
    enriched = state["enriched_context"]
    by_cand = {c["candidate_id"]: c for c in state["task_plan"]}
    host_ips = {h: rec.get("ip", "") for h, rec in enriched["hosts"].items()}
    groups = t.call("link_hosts", link_candidates, state["task_plan"], alerts_by_id, host_ips,
                    action="cross-host correlation (same user moving between hosts)",
                    inputs=f"{len(state['task_plan'])} candidates",
                    show=lambda g: f"{len(g)} incidents; merged: {[x for x in g if len(x) > 1] or 'none'}")

    incidents, severity = [], {}
    for group in groups:
        alert_ids = [a for cid in group for a in by_cand[cid]["alert_ids"]]
        inc = t.call("correlate", correlate, group[0], [alerts_by_id[i] for i in alert_ids], enriched,
                     action="correlate alerts (kill-chain rules)", inputs=" + ".join(group),
                     show=lambda r: f"stages={r['stages'] or 'none'}, hosts={r['hosts']}, intel={r['intel_verdict']}")
        inc["candidates"] = group
        parts = t.call("score_severity", score_severity, inc, action="score severity (rubric)", inputs=inc["id"],
                       show=lambda p: f"{p['total']} = {p['stage_points']}+{p['asset_points']}+{p['intel_points']}+{p['behaviour_points']}")
        apply_score(inc, parts, attempt)
        incidents.append(inc)

    inject_executor_faults(incidents, cfg, attempt, t)

    halluc = faults.active(cfg, "hallucinate", attempt)
    serious = sorted([i for i in incidents if i["band"] != "low"], key=lambda i: -i["severity"])
    halluc_target = serious[min(halluc["pick"], len(serious) - 1)]["id"] if halluc and serious else None
    prose = []
    for inc in incidents:
        if inc["band"] != "low":
            facts = {"id": inc["id"], "host": inc["host"], "hosts": inc["hosts"], "asset": inc["asset_criticality"],
                     "users": inc["users"], "stages": inc["stages"], "intel": inc["intel_verdict"],
                     "behaviour": inc["behaviour"], "severity": inc["severity"], "label": inc["label"]}
            text, record, entries = grounded_write(llm, "incident_summary", facts, inc["id"], "Executor",
                                                   enforce=enforced(state), inject_fault=inc["id"] == halluc_target)
            t.log("write incident summary", f"llm.write ({llm.name})", inc["id"], text)
            t.entries += entries
            inc["summary"] = text
            prose.append(record)
        else:
            inc["summary"] = f"{inc['id']} on {inc['host']}: low-severity activity ({inc['severity']}/100)."
        severity[inc["id"]] = inc["severity"]

    bands = {b: sum(1 for i in incidents if i["band"] == b) for b in ("high", "medium", "low")}
    t.log(f"attempt {attempt} complete", "", f"{len(incidents)} incidents", bands)
    return {"incidents": incidents, "severity": severity, "prose_checks": prose, "trace": t.entries}
