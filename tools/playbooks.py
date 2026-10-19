"""Incident-response playbook builder and the order-safety rules the Critic enforces."""
from __future__ import annotations

from tools.enrichment import is_external

REQUIRED_PHASES = ["preserve_evidence", "contain", "eradicate", "recover"]


def _iocs(alerts: list[dict], enriched: dict) -> dict[str, list[str]]:
    bad = {"ips": set(), "domains": set(), "hashes": set()}
    for a in alerts:
        intel = enriched["alerts"][a["id"]]["intel"]
        for field, key in (("src_ip", "ips"), ("dst_ip", "ips"), ("domain", "domains"), ("hash", "hashes")):
            value = a.get(field)
            if value and intel.get(value) in ("malicious", "suspicious"):
                bad[key].add(value)
        if a["src_ip"] and is_external(a["src_ip"]) and a["rule_name"] == "Failed login":
            bad["ips"].add(a["src_ip"])
    return {k: sorted(v) for k, v in bad.items()}


def build_playbook(incident: dict, alerts: list[dict], enriched: dict, unsafe: bool = False) -> list[dict]:
    """Ordered response steps. `unsafe=True` (fault) isolates the host before preserving evidence."""
    stages = incident["stages"]
    host = ", ".join(incident.get("hosts", [incident["host"]]))
    ioc = _iocs(alerts, enriched)
    users = ", ".join(incident["users"]) or "n/a"
    steps = [
        ("identify", f"Confirm alerts {incident['alert_ids'][0]}..{incident['alert_ids'][-1]} are true "
                     f"positives and search all hosts for {', '.join(sum(ioc.values(), [])[:3]) or 'the indicators'}",
         "SOC L2"),
        ("preserve_evidence", f"Capture memory image and disk snapshot of {host} before any change", "DFIR"),
        ("preserve_evidence", "Export auth, EDR, DNS and firewall logs for the incident window to the evidence store",
         "SOC L2"),
    ]
    if ioc["ips"]:
        steps.append(("contain", f"Block {', '.join(ioc['ips'])} at the perimeter firewall (simulated)", "Network"))
    if ioc["domains"]:
        steps.append(("contain", f"Sinkhole {', '.join(ioc['domains'])} at DNS and proxy (simulated)", "Network"))
    if "persistence" in stages or "initial_access" in stages or "lateral_movement" in stages:
        steps.append(("contain", f"Disable newly created accounts and reset credentials for {users}", "IAM"))
    steps.append(("contain", f"Isolate {host} from the network via EDR (simulated)", "EDR"))
    if "persistence" in stages:
        steps.append(("eradicate", f"Remove rogue admin account and audit scheduled tasks/services on {host}", "IAM"))
    if "lateral_movement" in stages:
        steps.append(("eradicate", f"Remove remotely created services and rotate credentials of {users} "
                                   "domain-wide (assume all cached credentials are stolen)", "IAM"))
    if "execution" in stages or ioc["hashes"]:
        steps.append(("eradicate", f"Remove malware ({', '.join(h[:12] + '…' for h in ioc['hashes']) or 'payload'}) "
                                   f"and reimage {host} if persistence is found", "EDR"))
    if not any(p == "eradicate" for p, _, _ in steps):
        steps.append(("eradicate", f"Remove attacker access paths found on {host}", "SOC L2"))
    if "impact" in stages:
        steps.append(("recover", f"Restore encrypted data on {host} from offline backups and verify integrity",
                      "IT Ops"))
    steps += [
        ("recover", f"Restore {host} from known-good state, enforce MFA for {users}, monitor for 72h", "IT Ops"),
        ("lessons_learned", "Deploy the new detection rule and record lessons learned in the ticket", "SOC Lead"),
    ]
    if unsafe:
        isolate = next(s for s in steps if s[2] == "EDR" and s[0] == "contain")
        steps.remove(isolate)
        steps.insert(1, isolate)
    return [{"order": i, "phase": p, "action": a, "owner": o} for i, (p, a, o) in enumerate(steps, start=1)]


def check_playbook_order(steps: list[dict]) -> list[str]:
    """Problems with the playbook order (empty list = safe)."""
    problems = []
    phases = [s["phase"] for s in steps]
    for phase in REQUIRED_PHASES:
        if phase not in phases:
            problems.append(f"Playbook has no '{phase}' step")
    if problems:
        return problems
    first = {p: phases.index(p) for p in REQUIRED_PHASES}
    last = {p: len(phases) - 1 - phases[::-1].index(p) for p in REQUIRED_PHASES}
    if first["contain"] < last["preserve_evidence"]:
        bad = steps[first["contain"]]
        problems.append(f"Step {bad['order']} ({bad['action']}) runs before evidence is preserved; "
                        "evidence would be destroyed")
    if first["eradicate"] < last["contain"]:
        problems.append("Eradication starts before containment is complete")
    if first["recover"] < last["eradicate"]:
        problems.append("Recovery starts before eradication is complete")
    return problems
