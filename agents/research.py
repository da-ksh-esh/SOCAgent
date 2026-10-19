"""2 Research agent: decides which enrichment tools to call for each candidate, then calls them.

Decision: for suspicious candidates the LLM plans the investigation (which indicators to look up,
which hosts/users to profile, which indicators to hunt across the estate). Its plan is validated:
only known tools, and only arguments that appear in the candidate's own alerts. Quiet candidates
(only low-severity, internal activity) get the standard enrichment checklist without a model call.
On a retry it executes exactly the lookups the Critic reported missing.
"""
from __future__ import annotations

from collections import Counter

from core import faults
from core import memory as analyst_memory
from core.llm import get_llm
from core.state import SOCState
from core.trace import Tracer
from tools.enrichment import (anomaly_reasons, asset_get, hunt_indicator, indicators, is_external,
                              threat_intel_lookup, user_baseline)

TOOLS = ("threat_intel.lookup", "assets.get", "users.baseline", "hunt.indicator")
SUSPICIOUS_SEVERITY = {"medium", "high", "critical"}


def indicator_type(value: str) -> str:
    if value.count(".") == 3 and value.replace(".", "").isdigit():
        return "ip"
    if len(value) >= 32 and all(c in "0123456789abcdef" for c in value):
        return "hash"
    return "domain"


def needs_investigation(alerts: list[dict]) -> bool:
    """Worth an LLM-planned investigation: anything above low severity, external IPs or files."""
    return any(a["raw_severity"] in SUSPICIOUS_SEVERITY or a["hash"]
               or any(is_external(a[k]) for k in ("src_ip", "dst_ip") if a[k]) for a in alerts)


def candidate_facts(cand: dict, alerts: list[dict]) -> dict:
    inds: dict[str, set] = {}
    for a in alerts:
        for ioc in indicators(a):
            inds.setdefault(ioc, set()).add(a["rule_name"])
    return {
        "candidate": cand["candidate_id"], "window": f"{cand['window'][0]} to {cand['window'][1]}",
        "hosts": sorted({a["host"] for a in alerts}), "users": sorted({a["user"] for a in alerts if a["user"]}),
        "rules": dict(Counter(a["rule_name"] for a in alerts)),
        "indicators": [{"value": v, "type": indicator_type(v), "external": indicator_type(v) != "ip" or is_external(v),
                        "rules": sorted(r)} for v, r in sorted(inds.items())],
    }


def validate(calls: list[dict], facts: dict) -> tuple[list[tuple[str, str]], list[str]]:
    """Keep only known tools whose argument is one of this candidate's own entities."""
    allowed = {"assets.get": set(facts["hosts"]), "users.baseline": set(facts["users"]),
               "threat_intel.lookup": {i["value"] for i in facts["indicators"]},
               "hunt.indicator": {i["value"] for i in facts["indicators"]}}
    ok, rejected = [], []
    for c in calls:
        tool, arg = str(c.get("tool", "")), str(c.get("arg", ""))
        if tool in allowed and arg in allowed[tool]:
            if (tool, arg) not in ok:
                ok.append((tool, arg))
        else:
            rejected.append(f"{tool}({arg[:24]})")
    return ok, rejected


def research_node(state: SOCState) -> dict:
    t = Tracer("Research")
    cfg = state["config"]
    data_dir = cfg["data_dir"]
    mem = analyst_memory.load() if cfg.get("use_memory") else None
    llm = get_llm(cfg)
    alerts_by_id = {a["id"]: a for a in state["alerts"]}
    prev = state.get("enriched_context") or {}
    ctx = {k: dict(prev.get(k, {})) for k in ("intel", "hosts", "users", "hunts", "plans")}
    performed = {tuple(x) for x in prev.get("performed", [])}
    attempt = prev.get("attempt", 0) + 1

    def run_call(tool: str, arg: str, why: str) -> None:
        if (tool, arg) in performed:
            return
        performed.add((tool, arg))
        if tool == "threat_intel.lookup":
            ctx["intel"][arg] = t.call(tool, threat_intel_lookup, arg, data_dir, mem, action=why, inputs=arg,
                                       show=lambda r: r["reputation"] + (f" ({r['source']})" if r["source"] != "threat feed" else "")
                                       + (f" - {r['note']}" if r["note"] else ""))
        elif tool == "assets.get":
            ctx["hosts"][arg] = t.call(tool, asset_get, arg, data_dir, action=why, inputs=arg,
                                       show=lambda r: f"{r['criticality']} ({r['role']})")
        elif tool == "users.baseline":
            ctx["users"][arg] = t.call(tool, user_baseline, arg, data_dir, mem, action=why, inputs=arg,
                                       show=lambda r: r and f"hours {r['work_hours']}, hosts {r['usual_hosts'][:3]}"
                                       + (f", learned {r['learned']}" if r.get("learned") else ""))
        elif tool == "hunt.indicator":
            ctx["hunts"][arg] = t.call(tool, hunt_indicator, arg, state["alerts"], action=why, inputs=arg,
                                       show=lambda r: f"{r['alerts']} alert(s) on {', '.join(r['hosts'])}")

    if attempt == 1:
        llm_used = 0
        fault = faults.active(cfg, "skip_lookup", 1)
        ranked = sorted(state["task_plan"], key=lambda c: -sum(
            alerts_by_id[a]["raw_severity"] in SUSPICIOUS_SEVERITY for a in c["alert_ids"]))
        fault_target = ranked[min(fault["pick"], len(ranked) - 1)]["candidate_id"] if fault else None
        for cand in state["task_plan"]:
            group = [alerts_by_id[a] for a in cand["alert_ids"]]
            facts = candidate_facts(cand, group)
            if needs_investigation(group):
                plan = t.call(f"llm.plan ({llm.name})", llm.plan, "investigation", facts,
                              action="plan investigation (choose tools)", inputs=cand["candidate_id"],
                              show=lambda p: f"{len(p['calls'])} tool calls · {p['rationale'][:90]}")
                calls, rejected = validate(plan["calls"], facts)
                planner, rationale = "llm", plan["rationale"]
                llm_used += 1
                if rejected:
                    t.log("rejected invalid tool calls", "plan_validator", cand["candidate_id"], rejected, status="fail")
            else:
                calls = [("assets.get", h) for h in facts["hosts"]] + [("users.baseline", u) for u in facts["users"]] + \
                        [("threat_intel.lookup", i["value"]) for i in facts["indicators"]]
                planner, rationale, rejected = "checklist", "Low-severity internal activity: standard enrichment.", []
            if cand["candidate_id"] == fault_target:
                skip = next((c for c in calls if c[0] == "threat_intel.lookup" and
                             next(i for i in facts["indicators"] if i["value"] == c[1])["external"]), None)
                skip = skip or next((c for c in calls if c[0] == "threat_intel.lookup"), None)
                if skip:
                    calls.remove(skip)
                    t.log("DEMO FAULT: skipped a threat-intel lookup", "fault_injector", cand["candidate_id"],
                          f"{skip[1][:30]} not looked up", status="fault")
            ctx["plans"][cand["candidate_id"]] = {"planner": planner, "rationale": rationale,
                                                  "calls": [list(c) for c in calls], "rejected": rejected}
            for tool, arg in calls:
                run_call(tool, arg, f"{cand['candidate_id']}: {tool.split('.')[0].replace('_', ' ')}")
        t.log("investigation plans complete", "", f"{len(state['task_plan'])} candidates",
              f"{llm_used} planned by the LLM, {len(state['task_plan']) - llm_used} by checklist")
    else:
        cp1 = [v for v in state["critic_verdicts"] if v["checkpoint"] == 1]
        latest = max((v["attempt"] for v in cp1), default=0)
        missing = list(dict.fromkeys(tuple(m) for v in cp1 if v["attempt"] == latest and not v["passed"]
                                     for m in v.get("missing", [])))
        t.log(f"attempt {attempt}: running lookups the Critic found missing", "", f"{len(missing)} lookups",
              "; ".join(f"{m[0]}({m[1][:20]})" for m in missing[:4]))
        for tool, arg in missing:
            run_call(tool, arg, "fill gap reported by Critic")

    per_alert = {}
    for a in state["alerts"]:
        per_alert[a["id"]] = {
            "intel": {ioc: ctx["intel"][ioc]["reputation"] for ioc in indicators(a) if ioc in ctx["intel"]},
            "anomaly_reasons": anomaly_reasons(a, ctx["users"].get(a["user"])) if a["user"] in ctx["users"] else [],
        }
    bad = sorted(k for k, v in ctx["intel"].items() if v["reputation"] in ("malicious", "suspicious"))
    learned = sum(1 for v in ctx["intel"].values() if v.get("source") == "analyst memory")
    t.log("enrichment complete", "", f"attempt {attempt}",
          f"{len(performed)} lookups, {len(bad)} bad indicators" + (f", {learned} from analyst memory" if learned else ""))
    return {"enriched_context": {**ctx, "alerts": per_alert, "performed": sorted(performed), "attempt": attempt},
            "trace": t.entries}
