"""Correlation engine: fixed kill-chain rules, cross-host linking and severity scoring.

detect_stages() is shared by the Executor (to build claims) and the Critic (to re-check only
the alerts a claim actually cites), so both apply exactly the same rules.
link_candidates() merges per-host candidates that are the same intrusion moving between hosts.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from core import rubric
from tools.enrichment import indicators, is_external, worst_verdict
from tools.mitre import techniques

KILL_CHAIN = ["reconnaissance", "delivery", "credential_access", "initial_access", "execution",
              "persistence", "lateral_movement", "command_and_control", "exfiltration", "impact"]
BRUTE_FORCE_MIN_FAILURES = 5
BEACON_MIN_CALLBACKS = 3
LINK_WINDOW = timedelta(minutes=60)
CRITICALITY_RANK = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "crown_jewel": 4}


def detect_stages(alerts: list[dict]) -> dict[str, list[str]]:
    """Map kill-chain stage -> supporting alert IDs, using deterministic rules."""
    by_rule: dict[str, list[dict]] = defaultdict(list)
    for a in sorted(alerts, key=lambda a: a["ts"]):
        by_rule[a["rule_name"]].append(a)
    ids = lambda items: [a["id"] for a in sorted(items, key=lambda a: a["ts"])]
    found: dict[str, list[str]] = {}

    if by_rule["Port scan detected"]:
        found["reconnaissance"] = ids(by_rule["Port scan detected"])
    if by_rule["Phishing link clicked"]:
        found["delivery"] = ids(by_rule["Phishing link clicked"])
    cred = list(by_rule["Credential dumping detected"])
    if len(by_rule["Failed login"]) >= BRUTE_FORCE_MIN_FAILURES:
        cred += by_rule["Failed login"]
    if cred:
        found["credential_access"] = ids(cred)
    external_logins = [a for a in by_rule["Successful login"] if is_external(a["src_ip"])]
    if len(by_rule["Failed login"]) >= BRUTE_FORCE_MIN_FAILURES and external_logins:
        found["initial_access"] = ids(external_logins)
    if by_rule["Suspicious file download"]:
        found["execution"] = ids(by_rule["Suspicious file download"])
    if by_rule["New admin account created"]:
        found["persistence"] = ids(by_rule["New admin account created"])
    remote = by_rule["Remote logon"]
    if by_rule["Remote service created"] or len({a["host"] for a in remote}) >= 2:
        found["lateral_movement"] = ids(remote + by_rule["Remote service created"])
    if len(by_rule["Beaconing detected"]) >= BEACON_MIN_CALLBACKS:
        found["command_and_control"] = ids(by_rule["Beaconing detected"])
    if by_rule["Large outbound transfer"]:
        found["exfiltration"] = ids(by_rule["Large outbound transfer"])
    impact = by_rule["Shadow copies deleted"] + by_rule["Mass file encryption"]
    if impact:
        found["impact"] = ids(impact)
    return {s: found[s] for s in KILL_CHAIN if s in found}


def link_candidates(candidates: list[dict], alerts_by_id: dict[str, dict], host_ips: dict[str, str]) -> list[list[str]]:
    """Group candidate IDs that are one intrusion spreading across hosts.

    Two candidates are linked when an alert in one comes from the IP of the other's host,
    for the same (non-empty) user, within LINK_WINDOW of the other candidate's activity.
    Returns lists of candidate IDs (singletons for unlinked candidates), in time order.
    """
    parent = {c["candidate_id"]: c["candidate_id"] for c in candidates}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    ip_to_cands: dict[str, list[dict]] = defaultdict(list)
    for c in candidates:
        if c["host"] in host_ips:
            ip_to_cands[host_ips[c["host"]]].append(c)
    for c in candidates:
        for aid in c["alert_ids"]:
            a = alerts_by_id[aid]
            if not a["user"] or not a["src_ip"] or a["src_ip"] == host_ips.get(c["host"]):
                continue
            t = datetime.fromisoformat(a["ts"])
            for other in ip_to_cands.get(a["src_ip"], []):
                if other is c or a["user"] not in other["users"]:
                    continue
                o_start = datetime.fromisoformat(other["window"][0]) - LINK_WINDOW
                o_end = datetime.fromisoformat(other["window"][1]) + LINK_WINDOW
                if o_start <= t <= o_end:
                    parent[find(c["candidate_id"])] = find(other["candidate_id"])
    groups: dict[str, list[str]] = defaultdict(list)
    for c in sorted(candidates, key=lambda c: c["window"][0]):
        groups[find(c["candidate_id"])].append(c["candidate_id"])
    return list(groups.values())


def stage_claim(stage: str, ids: list[str], alerts_by_id: dict[str, dict]) -> str:
    rules = [alerts_by_id[i]["rule_name"] for i in ids]
    hosts = sorted({alerts_by_id[i]["host"] for i in ids})
    if stage == "credential_access":
        parts = []
        if "Credential dumping detected" in rules:
            parts.append("credential dumping from LSASS memory")
        if rules.count("Failed login"):
            parts.append(f"{rules.count('Failed login')} failed logins (brute-force threshold {BRUTE_FORCE_MIN_FAILURES})")
        return "Credential access: " + " and ".join(parts)
    return {
        "reconnaissance": f"Reconnaissance: {len(ids)} port-scan alert(s)",
        "delivery": "Delivery: user clicked a phishing link",
        "initial_access": "Initial access: successful login from an external IP after failures",
        "execution": "Execution: suspicious file downloaded",
        "persistence": "Persistence: new administrator account created",
        "lateral_movement": f"Lateral movement: remote logons/services across {', '.join(hosts)}",
        "command_and_control": f"Command and control: {len(ids)} periodic callbacks",
        "exfiltration": f"Exfiltration: {len(ids)} large outbound transfer(s)",
        "impact": f"Impact: recovery inhibited and files encrypted ({len(ids)} alerts)",
    }[stage]


def host_record(host: str, enriched: dict) -> dict:
    return enriched["hosts"].get(host) or {"host": host, "criticality": "unknown", "role": "not looked up", "owner": "?"}


def correlate(incident_id: str, alerts: list[dict], enriched: dict) -> dict:
    """Turn one candidate group (possibly spanning hosts) into an incident with evidence-backed claims."""
    alerts = sorted(alerts, key=lambda a: a["ts"])
    by_id = {a["id"]: a for a in alerts}
    hosts = sorted({a["host"] for a in alerts}, key=lambda h: -CRITICALITY_RANK[host_record(h, enriched)["criticality"]])
    primary = hosts[0]
    stages = detect_stages(alerts)
    claims = [{"kind": "stage", "stage": s, "alert_ids": list(ids), "text": stage_claim(s, ids, by_id)}
              for s, ids in stages.items()]

    asset = host_record(primary, enriched)
    first_on_primary = next(a["id"] for a in alerts if a["host"] == primary)
    claims.append({"kind": "asset", "alert_ids": [first_on_primary],
                   "text": f"Host {primary} is a {asset['criticality']} asset ({asset['role']}, {asset['owner']})"
                           + (f"; activity spans {len(hosts)} hosts" if len(hosts) > 1 else "")})

    reps: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for a in alerts:
        for ioc in indicators(a):
            rep = enriched["alerts"][a["id"]]["intel"].get(ioc, "unknown")
            reps[rep].append((ioc, a["id"]))
    intel = worst_verdict(list(reps))
    hits = reps.get(intel, [])
    iocs = sorted({ioc for ioc, _ in hits})
    claims.append({"kind": "intel", "alert_ids": sorted({aid for _, aid in hits}) or [alerts[0]["id"]],
                   "text": f"Threat intel: {intel}" + (f" ({', '.join(i[:20] for i in iocs[:3])})" if hits else "")})

    anomalous = [a["id"] for a in alerts if enriched["alerts"][a["id"]]["anomaly_reasons"]]
    behaviour = "anomalous" if anomalous else "normal"
    reasons = sorted({r for a in alerts for r in enriched["alerts"][a["id"]]["anomaly_reasons"]})
    claims.append({"kind": "behaviour", "alert_ids": anomalous or [alerts[0]["id"]],
                   "text": f"Behaviour: {behaviour}" + (f" ({'; '.join(reasons[:2])})" if reasons else "")})

    return {
        "id": incident_id, "host": primary, "hosts": hosts, "users": sorted({a["user"] for a in alerts if a["user"]}),
        "alert_ids": [a["id"] for a in alerts], "start": alerts[0]["ts"], "end": alerts[-1]["ts"],
        "stages": list(stages), "techniques": techniques(stages, by_id), "claims": claims,
        "asset_criticality": asset["criticality"], "intel_verdict": intel, "behaviour": behaviour,
        "rule_names": sorted({a["rule_name"] for a in alerts}),
    }


def score_severity(incident: dict) -> dict:
    """Executor's score: rubric applied to the incident's own correlation result."""
    return rubric.compute_severity(len(incident["stages"]), incident["asset_criticality"],
                                   incident["intel_verdict"], incident["behaviour"])
