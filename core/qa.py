"""Grounded Q&A over a finished run.

Retrieval is deterministic Python: the question is matched to incidents (by ID, host, user, alert ID
or indicator) and to topics (score, Critic, playbook, rule, ticket, ATT&CK, ...), and only facts
pulled from the run state are passed on. The LLM (mock or Ollama) only words the answer from
those facts, and every answer lists the incident and alert IDs it is based on.
"""
from __future__ import annotations

import re

from core import memory as analyst_memory

TOPICS = {
    "score": ["score", "severity", "rubric", "points", "rated", "how bad", "how serious"],
    "critic": ["critic(?!al)", "reject", "retry", "retries", "verdict", "validat", "fail", "checkpoint", "flag"],
    "playbook": ["playbook", "contain", "respond", "response", "isolate", "steps", "remediat", "do next",
                 "should we", "we should", "what to do", "next step", "fix", "mitigat"],
    "rule": ["rule", "detection", "sigma", "test", "false positive"],
    "ticket": ["ticket", "sla", "assign", "priority", "notif", "slack", "email", "owner"],
    "attack": ["mitre", "att&ck", "attack technique", "technique", "tactic", "ttp"],
    "approval": ["approv", "human", "analyst decision", "hitl"],
    "evidence": ["evidence", "alert", "timeline", "what happened", "claims", "ioc", "indicator"],
    "closed": ["auto-close", "auto close", "closed", "benign", "noise", "dismiss"],
    "research": ["research", "investigat", "lookup", "look up", "tool", "plan"],
    "memory": ["memory", "learn", "taught", "allow-list", "allowlist", "block-list", "false positive"],
    "factcheck": ["fact-check", "fact check", "hallucinat", "rewrite"],
    "overview": ["summary", "overview", "how many", "total", "list", "which incidents", "everything", "run"],
}
TOP_WORDS = ["highest", "most severe", "worst", "top", "biggest", "most critical", "riskiest"]


def detect_topics(question: str) -> list[str]:
    """Topics the question is about; keywords match at the start of a word (patterns may be regex)."""
    q = question.lower()
    return [topic for topic, words in TOPICS.items() if any(re.search(r"\b" + w, q) for w in words)]


def find_incidents(question: str, state: dict) -> list[dict]:
    """Incidents the question refers to, most severe first."""
    q = question.lower()
    incidents = sorted(state["incidents"], key=lambda i: -i["severity"])
    by_alert = {a: i for i in incidents for a in i["alert_ids"]}
    alerts_by_id = {a["id"]: a for a in state["alerts"]}
    hits: list[dict] = []

    def add(inc):
        if inc not in hits:
            hits.append(inc)

    for iid in re.findall(r"inc-\d+", q):
        for i in incidents:
            if i["id"].lower() == iid:
                add(i)
    for aid in re.findall(r"(?:alt|live)-\d+", q):
        if aid.upper() in by_alert:
            add(by_alert[aid.upper()])
    for i in incidents:
        if i["host"].lower() in q or any(u.lower() in q for u in i["users"]):
            add(i)
        for aid in i["alert_ids"]:
            a = alerts_by_id[aid]
            if any(v and v.lower() in q for v in (a["src_ip"], a["dst_ip"], a["domain"], a["hash"])):
                add(i)
                break
    for t in ("brute force", "phishing", "ransomware", "exfiltration", "beacon", "encrypt"):
        if t in q:
            stage = {"brute force": "credential_access", "phishing": "delivery", "ransomware": "impact",
                     "encrypt": "impact", "exfiltration": "exfiltration", "beacon": "command_and_control"}[t]
            for i in incidents:
                if stage in i["stages"] and i["route"] != "auto_close":
                    add(i)
    if any(w in q for w in TOP_WORDS):
        add(incidents[0])
    # Prefer real incidents over the long tail of auto-closed noise on the same host.
    serious = [i for i in hits if i["route"] != "auto_close"]
    return (serious or hits)[:3]


def overview_facts(state: dict) -> list[str]:
    inc = state["incidents"]
    routes = {r: [i for i in inc if i["route"] == r] for r in ("escalate", "analyst_queue", "auto_close")}
    facts = [f"The run triaged {len(state['alerts'])} alerts into {len(inc)} candidate incidents: "
             f"{len(routes['escalate'])} escalated, {len(routes['analyst_queue'])} queued for an analyst, "
             f"{len(routes['auto_close'])} auto-closed.",
             f"The Critic sent work back {state['retries']['cp1'] + state['retries']['cp2']} time(s) "
             f"({state['retries']['cp1']} at checkpoint 1, {state['retries']['cp2']} at checkpoint 2)."]
    for i in sorted(routes["escalate"] + routes["analyst_queue"], key=lambda i: -i["severity"]):
        facts.append(f"{i['id']}: {i['headline']}, severity {i['severity']} "
                     f"({i['label']}), routed to {i['route'].replace('_', ' ')}"
                     + (" — flagged for human review" if i.get("needs_human_review") else "") + ".")
    return facts


def incident_facts(inc: dict, state: dict, topics: list[str]) -> list[str]:
    iid = inc["id"]
    show = set(topics) or {"score", "evidence", "critic"}
    facts = [f"{inc['summary']} Users involved: {', '.join(inc['users']) or 'none'}."]
    if "score" in show:
        b = inc["score_breakdown"]
        facts.append(f"{iid} score {b['total']} = {b['stage_points']} for {len(inc['stages'])} kill-chain stage(s) "
                     f"+ {b['asset_points']} asset ({inc['asset_criticality']}) + {b['intel_points']} threat intel "
                     f"({inc['intel_verdict']}) + {b['behaviour_points']} behaviour ({inc['behaviour']}). "
                     f"Route: {inc['route'].replace('_', ' ')}.")
    if "evidence" in show or "score" in show:
        for c in inc["claims"]:
            ids = c["alert_ids"]
            facts.append(f"{iid} claim: {c['text']} [{', '.join(ids[:5])}{'…' if len(ids) > 5 else ''}]")
    if "attack" in show and inc.get("techniques"):
        facts.append(f"{iid} ATT&CK techniques: " + "; ".join(f"{t['id']} {t['name']} ({t['tactic']})"
                                                               for t in inc["techniques"]))
    if "critic" in show:
        for v in [v for v in state["critic_verdicts"] if v["incident_id"] == iid]:
            facts.append(f"{iid} Critic checkpoint {v['checkpoint']}, {v['target']} attempt {v['attempt']}: "
                         f"{'PASSED' if v['passed'] else 'REJECTED'} — {'; '.join(v['reasons'])}")
        if inc.get("needs_human_review"):
            facts.append(f"{iid} was flagged for human review because the Critic's retries were exhausted.")
    if "closed" in show and inc.get("close_note"):
        facts.append(inc["close_note"])
    if inc.get("checklist") and ("playbook" in show or "closed" in show or not topics):
        facts.append(f"{iid} analyst checklist: " + "; ".join(inc["checklist"]))
    if "playbook" in show and iid in state.get("playbook", {}):
        facts += [f"{iid} playbook step {s['order']} [{s['phase']}]: {s['action']} ({s['owner']})"
                  for s in state["playbook"][iid]]
    if "rule" in show and iid in state.get("detection_rule", {}):
        r = state["detection_rule"][iid]
        t = r["self_test"]
        steps = " then ".join(f"{s['rule_name']}×{s['min_count']}" for s in r["rule"]["detection"]["steps"])
        facts.append(f"{iid} detection rule {r['rule']['id']} (attempt {r['attempt']}): {steps} on the same host "
                     f"within {r['rule']['detection']['timeframe_min']} min; tests {t['tests_passed']}/"
                     f"{t['tests_total']} passed, silent on benign: {t['silent_on_benign']}.")
    if "research" in show:
        for cid in inc.get("candidates", [iid]):
            plan = state["enriched_context"].get("plans", {}).get(cid)
            if plan:
                facts.append(f"{iid} investigation of {cid} planned by {plan['planner']}: {len(plan['calls'])} tool calls"
                             + (f" — {plan['rationale']}" if plan["rationale"] else ""))
    if ("ticket" in show or "approval" in show) and iid in state.get("ticket", {}):
        k = state["ticket"][iid]
        facts.append(f"{iid} ticket {k['ticket_id']} {k['priority']} {k['status']}, queue {k['queue']}, "
                     f"assigned to {k['assignee'] or 'nobody'}, SLA {k['sla_minutes'] or 'n/a'} min"
                     + (f" (due {k['sla_due']})" if k["sla_due"] else "") + ".")
    if iid in state.get("approvals", {}) and ("approval" in show or "playbook" in show or "ticket" in show):
        d = state["approvals"][iid]
        facts.append(f"{iid} containment {d['decision']} by {d['by']}" + (f": {d['comment']}" if d["comment"] else ""))
    return facts


def gather_facts(question: str, state: dict) -> tuple[list[str], list[str], list[str]]:
    """Return (facts, topics, incident IDs used)."""
    topics = detect_topics(question)
    incidents = find_incidents(question, state)
    facts: list[str] = []
    if not incidents and not topics:
        topics = ["off_topic"]
    if incidents and re.search(r"\bwhy\b", question.lower()) and "score" not in topics:
        topics.append("score")  # "why is X so bad" is a question about how it was scored
    if not incidents and ("overview" in topics or "off_topic" in topics):
        facts += overview_facts(state)
    if "memory" in topics:
        mem = analyst_memory.load()
        facts += [f"Analyst memory allow-lists {k}: {v['note']}" for k, v in list(mem["allow"].items())[:5]]
        facts += [f"Analyst memory block-lists {k}: {v['note']}" for k, v in list(mem["block"].items())[:5]]
        facts += [f"Analyst memory widened the baseline of {u}: hosts {b['extra_hosts']}, hours {b['extra_hours']}"
                  for u, b in list(mem["baselines"].items())[:5]]
        if not (mem["allow"] or mem["block"] or mem["baselines"]):
            facts.append("Analyst memory is empty: no incident has been marked false positive or confirmed yet.")
    if "factcheck" in topics:
        checks = state.get("prose_checks", [])
        rejected = [c for c in checks if c["rejections"]]
        facts.append(f"The Critic fact-checked {len(checks)} LLM texts; {len(rejected)} were rejected and rewritten.")
        facts += [f"Fact-check of {c['kind'].replace('_', ' ')} for {c['subject']}: {c['rejections'][0][0]}; "
                  f"{'passed after rewrite' if c['passed'] else 'replaced by the factual template'}" for c in rejected[:4]]
    if "closed" in topics and not incidents:
        closed = [i for i in state["incidents"] if i["route"] == "auto_close"]
        facts.append(f"{len(closed)} incidents were auto-closed (severity below 40).")
        facts += [i["close_note"] for i in closed[:4]]
    if "attack" in topics and not incidents:
        seen = {}
        for i in state["incidents"]:
            if i["route"] != "auto_close":
                for t in i.get("techniques", []):
                    seen.setdefault(f"{t['id']} {t['name']}", []).append(i["id"])
        facts += [f"ATT&CK {k}: seen in {', '.join(v)}" for k, v in seen.items()]
    if "critic" in topics and not incidents:
        if all(v["passed"] for v in state["critic_verdicts"]):
            facts.append(f"The Critic approved all {len({v['incident_id'] for v in state['critic_verdicts']})} "
                         "incidents on the first attempt at both checkpoints; no work was sent back.")
        for v in [v for v in state["critic_verdicts"] if not v["passed"]]:
            facts.append(f"Critic checkpoint {v['checkpoint']} REJECTED {v['target']} attempt {v['attempt']} for "
                         f"{v['incident_id']}: {'; '.join(v['reasons'])}")
    if "ticket" in topics and not incidents:
        for k in [k for k in state.get("ticket", {}).values() if k["status"] == "Open"]:
            facts.append(f"{k['incident_id']} ticket {k['ticket_id']} {k['priority']}: {k['title']}, assigned to "
                         f"{k['assignee']}, SLA {k['sla_minutes']} min (due {k['sla_due']}).")
    if "research" in topics and not incidents:
        plans = state["enriched_context"].get("plans", {})
        llm_plans = [k for k, v in plans.items() if v["planner"] == "llm"]
        facts.append(f"The Research agent planned {len(llm_plans)} of {len(plans)} investigations with the LLM; "
                     "quiet candidates used the standard checklist.")
    if "approval" in topics and not incidents:
        facts += [f"{k} containment {d['decision']} by {d['by']}" for k, d in state.get("approvals", {}).items()]
    for inc in incidents:
        facts += incident_facts(inc, state, [t for t in topics if t != "overview"])
    if not facts:
        facts = overview_facts(state)
    return facts, topics, [i["id"] for i in incidents]


def answer(question: str, state: dict, llm) -> dict:
    """Retrieve facts, let the LLM word the answer, and have the Critic fact-check it (rewrite on rejection)."""
    from agents.critic import grounded_write

    facts, topics, incident_ids = gather_facts(question, state)
    text, check, _ = grounded_write(llm, "qa_answer", {"question": question, "facts": facts, "topics": topics},
                                    "chat answer", "Chat")
    alert_ids = sorted({a for f in facts for a in re.findall(r"(?:ALT|WIN)-\d{4}", f)})
    return {"answer": text, "facts": facts, "incidents": incident_ids, "alerts": alert_ids,
            "backend": check["backend"], "fact_check": check}
