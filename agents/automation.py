"""6 Business Automation agent: tickets, SLA timers, on-call assignment, mock notifications,
the incident report and the shift handover.

Decision: priority and SLA follow the severity label (critical 30 min, high 60, medium 240);
high incidents page Slack and email, medium incidents email the analyst queue. The LLM writes the
report prose and the Critic fact-checks it (rewrite on rejection).
"""
from __future__ import annotations

from datetime import datetime

from agents.critic import enforced, grounded_write
from core.llm import get_llm
from core.state import SOCState
from core.trace import Tracer
from tools.ticketing import create_ticket, notify

ROUTE_NAME = {"auto_close": "auto-close", "analyst_queue": "the analyst queue", "escalate": "incident response"}
CONTAINMENT = {"approved": "Approved: execute playbook containment",
               "rejected": "Rejected: containment on hold, investigate manually",
               "false_positive": "False positive: no containment; analyst memory updated"}


def incident_report_md(inc: dict, ticket: dict, rule: dict | None, playbook: list[dict] | None,
                       narrative: str, approval: dict | None = None) -> str:
    lines = [f"##### {inc['id']}: {inc['headline']}",
             f"**Severity:** {inc['severity']}/100 ({inc['label']}) · **Ticket:** {ticket['ticket_id']} "
             f"({ticket['priority']}, assigned to {ticket['assignee'] or 'n/a'}) · **Hosts:** {', '.join(inc['hosts'])}",
             "", narrative, "", "**Evidence**"]
    lines += [f"- {c['text']} — {', '.join(c['alert_ids'][:6])}{'…' if len(c['alert_ids']) > 6 else ''}"
              for c in inc["claims"]]
    if playbook:
        lines += ["", "**Response playbook**"] + [f"{s['order']}. [{s['phase']}] {s['action']} ({s['owner']})"
                                                for s in playbook]
    if approval:
        lines += ["", f"**Containment:** {approval['decision'].replace('_', ' ')} by {approval['by']}"
                      + (f" ({approval['comment']})" if approval.get("comment") else "")]
    if rule:
        lines += ["", f"**Detection rule:** {rule['rule']['id']} — tests "
                      f"{rule['self_test']['tests_passed']}/{rule['self_test']['tests_total']} passed"]
    if inc.get("checklist"):
        lines += ["", "**Analyst checklist**"] + [f"- [ ] {c}" for c in inc["checklist"]]
    return "\n".join(lines)


def automation_node(state: SOCState) -> dict:
    t = Tracer("Business Automation")
    llm = get_llm(state["config"])
    enforce = enforced(state)
    prose: list[dict] = []

    def write(kind: str, facts: dict, subject: str) -> str:
        text, record, entries = grounded_write(llm, kind, facts, subject, "Business Automation", enforce)
        t.log(f"write {kind.replace('_', ' ')}", f"llm.write ({llm.name})", subject, text)
        t.entries.extend(entries)
        prose.append(record)
        return text

    now = datetime.now().replace(second=0, microsecond=0)
    incidents = sorted(state["incidents"], key=lambda i: -i["severity"])
    tickets, notes, reports = {}, [], {}
    approvals = state.get("approvals", {})

    for n, inc in enumerate(incidents, start=1):
        ticket = create_ticket(n, inc, now)
        if inc["id"] in approvals:
            d = approvals[inc["id"]]
            ticket["containment"] = CONTAINMENT[d["decision"]]
            ticket["approved_by"] = d["by"]
            if d["decision"] == "false_positive":
                ticket["status"] = "Closed"
        tickets[inc["id"]] = ticket
        if inc["route"] != "auto_close":
            t.log("create ticket + start SLA timer", "ticketing.create", inc["id"],
                  f"{ticket['ticket_id']} {ticket['priority']} SLA {ticket['sla_minutes']}m -> {ticket['assignee']}")
        if inc["route"] == "escalate" and ticket["status"] == "Open":
            msg = (f"{ticket['priority']} {inc['headline']} (score {inc['severity']}). Ticket {ticket['ticket_id']}."
                   + (f" Containment {approvals[inc['id']]['decision'].replace('_', ' ')}." if inc["id"] in approvals else ""))
            notes.append(t.call("notifier.slack", notify, "slack", "#soc-critical", msg, now,
                                action="page on-call via Slack (mock)", inputs=inc["id"],
                                show=lambda r: f"{r['to']}: {r['delivered']}"))
            notes.append(t.call("notifier.email", notify, "email", f"{ticket['assignee']}", msg, now,
                                action="email assigned analyst (mock)", inputs=inc["id"],
                                show=lambda r: f"{r['to']}: {r['delivered']}"))
        elif inc["route"] == "analyst_queue":
            notes.append(t.call("notifier.email", notify, "email", "soc-queue@example.local",
                                f"{ticket['priority']} {inc['headline']} queued for review.", now,
                                action="email analyst queue (mock)", inputs=inc["id"],
                                show=lambda r: f"{r['to']}: {r['delivered']}"))
        if inc["route"] != "auto_close":
            story = write("incident_report", {"id": inc["id"], "hosts": inc["hosts"], "start": inc["start"],
                                              "end": inc["end"], "stages": inc["stages"], "severity": inc["severity"],
                                              "route": ROUTE_NAME[inc["route"]]}, inc["id"])
            reports[inc["id"]] = incident_report_md(inc, ticket, state["detection_rule"].get(inc["id"]),
                                                    state["playbook"].get(inc["id"]), story, approvals.get(inc["id"]))
    closed = sum(1 for i in incidents if i["route"] == "auto_close")
    t.log("auto-close low-severity incidents", "ticketing.create", f"{closed} incidents",
          f"{closed} tickets created as Closed with justification notes")

    counts = {r: sum(1 for i in incidents if i["route"] == r) for r in ("escalate", "analyst_queue", "auto_close")}
    retries = state["retries"]["cp1"] + state["retries"]["cp2"]
    narrative = write("report_narrative", {"alerts": len(state["alerts"]), "incidents": len(incidents),
                                           "high": counts["escalate"], "medium": counts["analyst_queue"],
                                           "low": counts["auto_close"], "retries": retries}, "run summary")
    rows = ["| Incident | Hosts | Severity | Route | Ticket | Assignee |", "|---|---|---|---|---|---|"]
    rows += [f"| {i['id']} | {', '.join(i['hosts'])} | {i['severity']} ({i['label']}) | {ROUTE_NAME[i['route']]} | "
             f"{tickets[i['id']]['ticket_id']} | {tickets[i['id']]['assignee'] or '-'} |"
             for i in incidents if i["route"] != "auto_close"]
    summary_md = "\n".join([f"#### SOC triage report — {now:%d %b %Y %H:%M}", "", narrative, "",
                            "##### Open incidents", *rows, "", *reports.values()])

    open_tickets = [tickets[i["id"]] for i in incidents if tickets[i["id"]]["status"] == "Open"]
    top = open_tickets[0]["title"] if open_tickets else "none"
    handover_text = write("handover", {"open": len(open_tickets), "top": top}, "shift handover")
    handover_md = "\n".join([f"#### Shift handover — {now:%d %b %Y %H:%M}", "", handover_text, "",
                             "| Ticket | Priority | Title | Assignee | SLA due |", "|---|---|---|---|---|",
                             *[f"| {k['ticket_id']} | {k['priority']} | {k['title']} | {k['assignee']} | "
                               f"{k['sla_due']}{' · needs human review' if k['needs_human_review'] else ''} |"
                               for k in open_tickets],
                             "", f"Auto-closed this shift: {counts['auto_close']} incidents (notes attached to "
                                 "closed tickets)."])
    t.log("workflow complete", "", "", f"{len(tickets)} tickets, {len(notes)} notifications, report + handover")
    return {"ticket": tickets, "notifications": notes, "trace": t.entries, "prose_checks": prose,
            "report": {"summary_md": summary_md, "handover_md": handover_md, "incidents_md": reports}}
