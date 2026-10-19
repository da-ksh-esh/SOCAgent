"""4 Critic agent: validates other agents' work and sends it back.

Checkpoint 1 (after Research + Executor)
  - Research: every indicator, host and user in the incident was actually looked up.
  - Executor: every claim cites real alert IDs from the incident, every claimed stage is supported
    by the cited alerts, and the severity recomputed independently from that evidence matches.
  Failures go back to Research (missing lookups) or the Executor (max rubric.MAX_RETRIES).
Checkpoint 2 (after Software Development)
  - The detection rule fires on attack logs and stays silent on benign logs; the playbook preserves
    evidence before containing the host.
Fact-check (whenever an LLM writes prose)
  - Every ID, IP, domain, hash, host and number in the text must appear in the facts it was given;
    otherwise the text is rejected and the model rewrites it (max 2 rewrites, then the factual template).

config["critic_enabled"] = False keeps the checks but never sends work back (ablation study).
"""
from __future__ import annotations

import json
import re

from core import faults, rubric
from core.paths import load_json
from core.state import SOCState
from core.trace import Tracer
from tools.correlate import CRITICALITY_RANK, detect_stages, host_record
from tools.enrichment import indicators, required_lookups, worst_verdict
from tools.playbooks import check_playbook_order
from tools.rules import run_rule_tests

MAX_REWRITES = 2


def enforced(state: SOCState) -> bool:
    return state["config"].get("critic_enabled", True)


# ------------------------------------------------------------------ fact-check of LLM prose

TOKEN_PATTERNS = {
    "ID": r"\b(?:INC|ALT|SOC|BEN|ATK)-[A-Z0-9-]*\d\b",
    "IP": r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
    "host": r"\b(?:SRV|WS|FIN|SCN)-[A-Z0-9]+\b",
    "hash": r"\b[0-9a-f]{12,64}\b",
    "domain": r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|top|xyz|us|local)\b",
}
FREE_NUMBERS = {"100"}


def fact_check(text: str, allowed: str) -> list[str]:
    """Problems with an LLM text: tokens it states that are not in the facts it was given."""
    problems = []
    for label, pattern in TOKEN_PATTERNS.items():
        for tok in sorted(set(re.findall(pattern, text))):
            if tok not in allowed:
                problems.append(f"mentions {label} '{tok}' that is not in the facts")
    stripped = text
    for pattern in TOKEN_PATTERNS.values():
        stripped = re.sub(pattern, " ", stripped)
    for num in sorted(set(re.findall(r"(?<![\w.:/-])\d{2,}(?![\w.:/-])", stripped))):
        if num not in FREE_NUMBERS and not re.search(rf"(?<!\d){num}(?!\d)", allowed):
            problems.append(f"states the number {num}, which is not in the facts")
    return problems


def grounded_write(llm, kind: str, facts: dict, subject: str, agent: str, enforce: bool = True,
                   inject_fault: bool = False) -> tuple[str, dict, list[dict]]:
    """LLM writes, Critic fact-checks, LLM rewrites on rejection. Returns (text, record, trace entries)."""
    t = Tracer("Critic")
    allowed = json.dumps(facts, default=str)
    feedback, rejections = None, []
    text = ""
    for attempt in range(1, MAX_REWRITES + 2):
        text = llm.write(kind, facts, feedback=feedback)
        if inject_fault and attempt == 1:
            text = text.rstrip(".") + f". Traffic also reached {faults.HALLUCINATED_IP}."
            t.log("DEMO FAULT: LLM hallucinated an IP", "fault_injector", subject, faults.HALLUCINATED_IP, status="fault")
        problems = fact_check(text, allowed)
        if not problems:
            if attempt > 1 or inject_fault:
                t.log("fact-check PASSED after rewrite", "fact_checker", f"{kind} · {subject}", f"attempt {attempt}",
                      status="pass")
            return text, {"agent": agent, "kind": kind, "subject": subject, "attempts": attempt,
                          "rejections": rejections, "passed": True, "replaced": False,
                          "backend": getattr(llm, "last_backend", llm.name)}, t.entries
        rejections.append(problems)
        t.log("fact-check REJECTED LLM text", "fact_checker", f"{kind} · {subject}", problems[0], status="fail")
        if not enforce:
            return text, {"agent": agent, "kind": kind, "subject": subject, "attempts": attempt,
                          "rejections": rejections, "passed": False, "replaced": False, "shipped": True,
                          "backend": getattr(llm, "last_backend", llm.name)}, t.entries
        feedback = "; ".join(problems)
    template = getattr(llm, "fallback", llm).write(kind, facts)   # facts filled into a fixed sentence
    t.log("rewrites exhausted: using the factual template", "fact_checker", f"{kind} · {subject}", "", status="fail")
    return template, {"agent": agent, "kind": kind, "subject": subject, "attempts": MAX_REWRITES + 1,
                      "rejections": rejections, "passed": False, "replaced": True,
                      "backend": "factual template"}, t.entries


# ------------------------------------------------------------------ checkpoint 1

def max_criticality(incident: dict, enriched: dict) -> str:
    return max((host_record(h, enriched)["criticality"] for h in incident.get("hosts", [incident["host"]])),
               key=lambda c: CRITICALITY_RANK[c])


def recompute_from_evidence(incident: dict, alerts_by_id: dict, enriched: dict) -> tuple[dict, list[str]]:
    """Critic's own score, built only from the alerts the claims cite. Never reads incident['severity']."""
    problems = []
    own_ids = set(incident["alert_ids"])
    for claim in incident["claims"]:
        if not claim["alert_ids"]:
            problems.append(f"Claim '{claim['text']}' cites no alert IDs")
        foreign = [i for i in claim["alert_ids"] if i not in own_ids or i not in alerts_by_id]
        if foreign:
            problems.append(f"Claim '{claim['text']}' cites alerts outside this incident: {foreign}")

    stage_ids = {i for c in incident["claims"] if c["kind"] == "stage" for i in c["alert_ids"] if i in own_ids}
    verified = detect_stages([alerts_by_id[i] for i in stage_ids])
    for stage in incident["stages"]:
        if stage not in verified:
            problems.append(f"Stage '{stage}' is not supported by the cited evidence")

    cited = [alerts_by_id[i] for c in incident["claims"] for i in c["alert_ids"] if i in own_ids]
    intel = worst_verdict([enriched["alerts"][a["id"]]["intel"].get(ioc, "unknown")
                           for a in cited for ioc in indicators(a)])
    behaviour = "anomalous" if any(enriched["alerts"][a["id"]]["anomaly_reasons"] for a in cited) else "normal"
    return rubric.compute_severity(len(verified), max_criticality(incident, enriched), intel, behaviour), problems


def missing_lookups(incident: dict, alerts_by_id: dict, enriched: dict) -> list[list[str]]:
    performed = {tuple(x) for x in enriched.get("performed", [])}
    need = required_lookups([alerts_by_id[a] for a in incident["alert_ids"]])
    return sorted([list(x) for x in need - performed])


def critic_cp1_node(state: SOCState) -> dict:
    t = Tracer("Critic")
    attempt = state["retries"]["cp1"] + 1
    alerts_by_id = {a["id"]: a for a in state["alerts"]}
    enriched = state["enriched_context"]
    verdicts = []
    for inc in state["incidents"]:
        missing = missing_lookups(inc, alerts_by_id, enriched)
        problems = [f"Research did not run {tool}({arg[:28]})" for tool, arg in missing]
        parts, evidence_problems = recompute_from_evidence(inc, alerts_by_id, enriched)
        problems += evidence_problems
        executor_score = state["severity"][inc["id"]]          # read only after computing our own
        if parts["total"] != executor_score:
            problems.append(f"Severity mismatch: Executor scored {executor_score}, "
                            f"Critic recomputed {parts['total']} from cited evidence")
        passed = not problems
        target = "Research" if missing else "Executor"
        verdicts.append({"checkpoint": 1, "attempt": attempt, "incident_id": inc["id"], "target": target,
                         "passed": passed, "reasons": problems or ["Lookups complete; claims cited; score matches rubric"],
                         "critic_score": parts["total"], "agent_score": executor_score, "missing": missing,
                         "enforced": enforced(state)})
        if not passed or inc["band"] != "low":
            t.log("checkpoint 1: lookups + evidence + rubric", "lookup_audit + evidence_checker + rubric_recompute",
                  inc["id"], ("REJECTED: " + problems[0]) if problems else f"PASSED (score {parts['total']} confirmed)",
                  status="fail" if problems else "pass")

    failed = [v for v in verdicts if not v["passed"]]
    retries = dict(state["retries"])
    status = dict(state.get("checkpoint_status", {}))
    incidents = state["incidents"]
    if not failed:
        status["cp1"] = "pass"
        t.log("checkpoint 1 PASSED", "", f"attempt {attempt}", f"{len(verdicts)} incidents approved -> router", status="pass")
    elif not enforced(state):
        status["cp1"] = "pass"
        t.log("checkpoint 1: problems found but Critic is DISABLED (ablation)", "", [v["incident_id"] for v in failed],
              "work ships unchanged", status="fault")
    elif retries["cp1"] < rubric.MAX_RETRIES:
        retries["cp1"] += 1
        status["cp1"] = "retry"
        status["cp1_target"] = "research" if any(v["missing"] for v in failed) else "executor"
        t.log(f"checkpoint 1 REJECTED: sending back to {status['cp1_target'].title()}", "",
              [v["incident_id"] for v in failed], f"retry {retries['cp1']}/{rubric.MAX_RETRIES}", status="fail")
    else:
        status["cp1"] = "flagged"
        bad = {v["incident_id"] for v in failed}
        incidents = [{**i, "needs_human_review": i["id"] in bad} for i in incidents]
        t.log("checkpoint 1: retries exhausted, flagging for human review", "", sorted(bad), "", status="fail")
    return {"critic_verdicts": verdicts, "retries": retries, "checkpoint_status": status,
            "incidents": incidents, "trace": t.entries}


# ------------------------------------------------------------------ checkpoint 2

def critic_cp2_node(state: SOCState) -> dict:
    t = Tracer("Critic")
    attempt = state["retries"]["cp2"] + 1
    data_dir = state["config"]["data_dir"]
    attack_logs = load_json("attack_logs.json", data_dir)
    benign_logs = load_json("benign_logs.json", data_dir)
    alerts_by_id = {a["id"]: a for a in state["alerts"]}
    verdicts = []
    for inc in [i for i in state["incidents"] if i["route"] == "escalate"]:
        bundle = state["detection_rule"][inc["id"]]
        own_alerts = [alerts_by_id[i] for i in inc["alert_ids"]]
        replay = attack_logs.get(bundle["rule"]["template"], own_alerts)
        tests = t.call("rule_test_runner", run_rule_tests, bundle["rule"], replay, benign_logs, own_alerts,
                       action="re-run detection rule tests independently", inputs=bundle["rule"]["id"],
                       show=lambda r: f"{r['tests_passed']}/{r['tests_total']} passed"
                                      + (f", false positives {r['false_positive_ids'][:3]}" if r["false_positive_ids"] else ""))
        problems = []
        if not tests["fires_on_attack_replay"]:
            problems.append("Rule does not fire on the replayed attack logs")
        if not tests["fires_on_incident"]:
            problems.append("Rule does not fire on this incident's own alerts")
        if not tests["silent_on_benign"]:
            problems.append(f"Rule fires on benign logs ({len(tests['false_positive_ids'])} false-positive "
                            f"events, e.g. {tests['false_positive_ids'][:2]})")
        problems += t.call("playbook_order_rules", check_playbook_order, state["playbook"][inc["id"]],
                           action="check playbook order", inputs=inc["id"], show=lambda p: "safe" if not p else p[0])
        verdicts.append({"checkpoint": 2, "attempt": attempt, "incident_id": inc["id"],
                         "target": "Software Development", "passed": not problems,
                         "reasons": problems or ["Rule fires on attack, silent on benign; playbook order safe"],
                         "rule_tests": tests, "enforced": enforced(state)})
        t.log("checkpoint 2: rule + playbook check", "", inc["id"],
              ("REJECTED: " + problems[0]) if problems else "PASSED", status="fail" if problems else "pass")

    failed = [v for v in verdicts if not v["passed"]]
    retries = dict(state["retries"])
    status = dict(state.get("checkpoint_status", {}))
    incidents = state["incidents"]
    if not failed:
        status["cp2"] = "pass"
        t.log("checkpoint 2 PASSED", "", f"attempt {attempt}", "rules and playbooks approved", status="pass")
    elif not enforced(state):
        status["cp2"] = "pass"
        t.log("checkpoint 2: problems found but Critic is DISABLED (ablation)", "", [v["incident_id"] for v in failed],
              "work ships unchanged", status="fault")
    elif retries["cp2"] < rubric.MAX_RETRIES:
        retries["cp2"] += 1
        status["cp2"] = "retry"
        t.log("checkpoint 2 REJECTED: sending back to Software Development", "",
              [v["incident_id"] for v in failed], f"retry {retries['cp2']}/{rubric.MAX_RETRIES}", status="fail")
    else:
        status["cp2"] = "flagged"
        bad = {v["incident_id"] for v in failed}
        incidents = [{**i, "needs_human_review": i.get("needs_human_review") or i["id"] in bad} for i in incidents]
        t.log("checkpoint 2: retries exhausted, flagging for human review", "", sorted(bad), "", status="fail")
    return {"critic_verdicts": verdicts, "retries": retries, "checkpoint_status": status,
            "incidents": incidents, "trace": t.entries}
