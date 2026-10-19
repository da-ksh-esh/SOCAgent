"""Detection-rule generator and test runner (Sigma-style rules evaluated in pure Python).

A rule is an ordered list of steps that must all occur, in order, on the same `group_by`
value (e.g. host) within `timeframe_min` minutes. Each step names a SIEM rule, a minimum
count and optionally requires the source IP to be external.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from tools.enrichment import is_external
from tools.mitre import RULE_TECHNIQUE

STAGE_TO_RULE = {
    "reconnaissance": "Port scan detected", "delivery": "Phishing link clicked",
    "credential_access": "Failed login", "initial_access": "Successful login",
    "execution": "Suspicious file download", "persistence": "New admin account created",
    "command_and_control": "Beaconing detected", "exfiltration": "Large outbound transfer",
    "lateral_movement": "Remote logon", "impact": "Mass file encryption",
}

# An over-broad single step used only by the "Inject fault" demo: it fires on benign noise.
BROKEN_STEP = {
    "brute_force": {"rule_name": "Failed login", "min_count": 1},
    "phishing_c2": {"rule_name": "Suspicious file download", "min_count": 1},
    "lateral_movement": {"rule_name": "Remote logon", "min_count": 1},
}


def template_for(stages: list[str]) -> str:
    if "lateral_movement" in stages:
        return "lateral_movement"
    if "credential_access" in stages and "initial_access" in stages:
        return "brute_force"
    if "command_and_control" in stages or "delivery" in stages:
        return "phishing_c2"
    return "generic"


def generate_rule(incident: dict, broken: bool = False) -> dict:
    """Build a detection rule from the incident's correlated kill-chain stages."""
    stages = incident["stages"]
    template = template_for(stages)
    if template == "brute_force":
        steps = [{"rule_name": "Failed login", "min_count": 5, "src_external": True},
                 {"rule_name": "Successful login", "min_count": 1, "src_external": True}]
        if "persistence" in stages:
            steps.append({"rule_name": "New admin account created", "min_count": 1})
        title, timeframe = "Brute force followed by external login and admin account creation", 30
    elif template == "phishing_c2":
        steps = []
        if "delivery" in stages:
            steps.append({"rule_name": "Phishing link clicked", "min_count": 1})
        if "execution" in stages:
            steps.append({"rule_name": "Suspicious file download", "min_count": 1})
        if "command_and_control" in stages:
            steps.append({"rule_name": "Beaconing detected", "min_count": 3})
        title, timeframe = "Phishing click followed by download and C2 beaconing", 60
    elif template == "lateral_movement":
        steps = [{"rule_name": "Credential dumping detected", "min_count": 1},
                 {"rule_name": "Remote logon", "min_count": 1}]
        title, timeframe = "Credential dumping followed by remote logon as the same user", 60
    else:
        steps = [{"rule_name": STAGE_TO_RULE[s], "min_count": 1} for s in stages]
        title, timeframe = f"Correlated activity: {' -> '.join(stages)}", 60

    if broken:
        steps = [dict(BROKEN_STEP.get(template, {**steps[0], "min_count": 1}))]
    return {
        "id": f"SOC-RULE-{incident['id']}", "title": title, "template": template,
        "status": "experimental", "level": "critical" if incident.get("severity", 0) >= 90 else "high",
        "tags": [f"attack.{s}" for s in stages] + sorted({f"attack.{RULE_TECHNIQUE[st['rule_name']][0].lower()}"
                                                           for st in steps if st["rule_name"] in RULE_TECHNIQUE}),
        "detection": {"steps": steps, "group_by": "user" if template == "lateral_movement" else "host",
                      "timeframe_min": timeframe},
    }


def _step_hit(step: dict, event: dict) -> bool:
    if event["rule_name"] != step["rule_name"]:
        return False
    return not step.get("src_external") or is_external(event.get("src_ip", ""))


def rule_matches(rule: dict, logs: list[dict]) -> list[list[str]]:
    """Return one list of matching event IDs per firing; empty list means the rule stayed silent."""
    det = rule["detection"]
    window = timedelta(minutes=det["timeframe_min"])
    groups: dict[str, list[dict]] = defaultdict(list)
    for e in logs:
        groups[e.get(det["group_by"], "")].append(e)

    firings = []
    for events in groups.values():
        events.sort(key=lambda e: e["ts"])
        for i, first in enumerate(events):
            if not _step_hit(det["steps"][0], first):
                continue
            start = datetime.fromisoformat(first["ts"])
            in_window = [e for e in events[i:] if datetime.fromisoformat(e["ts"]) <= start + window]
            matched, cursor, ok = [], 0, True
            for step in det["steps"]:
                hits = []
                while cursor < len(in_window) and len(hits) < step["min_count"]:
                    if _step_hit(step, in_window[cursor]):
                        hits.append(in_window[cursor]["id"])
                    cursor += 1
                if len(hits) < step["min_count"]:
                    ok = False
                    break
                matched += hits
            if ok:
                firings.append(matched)
                break  # one firing per group is enough
    return firings


def run_rule_tests(rule: dict, attack_logs: list[dict], benign_logs: list[dict],
                   incident_alerts: list[dict]) -> dict:
    """Positive tests (replayed attack + the incident itself) and a negative test (benign logs)."""
    attack_hits = rule_matches(rule, attack_logs)
    incident_hits = rule_matches(rule, incident_alerts)
    benign_hits = rule_matches(rule, benign_logs)
    result = {
        "fires_on_attack_replay": bool(attack_hits),
        "fires_on_incident": bool(incident_hits),
        "silent_on_benign": not benign_hits,
        "false_positive_ids": sorted({i for f in benign_hits for i in f}),
        "attack_samples": len(attack_logs), "benign_samples": len(benign_logs),
    }
    checks = ["fires_on_attack_replay", "fires_on_incident", "silent_on_benign"]
    result["tests_passed"] = sum(result[c] for c in checks)
    result["tests_total"] = len(checks)
    result["passed"] = result["tests_passed"] == len(checks)
    return result


def render_yaml(rule: dict) -> str:
    """Sigma-style YAML view of the rule (for display)."""
    det = rule["detection"]
    lines = [f"title: {rule['title']}", f"id: {rule['id']}", f"status: {rule['status']}",
             "logsource:", "  product: siem", "detection:"]
    for n, step in enumerate(det["steps"], start=1):
        lines.append(f"  step_{n}:")
        lines.append(f"    rule_name: '{step['rule_name']}'")
        if step.get("src_external"):
            lines.append("    src_ip|external: true")
    parts = [f"step_{n}" + (f" | count() >= {s['min_count']}" if s["min_count"] > 1 else "")
             for n, s in enumerate(det["steps"], start=1)]
    lines += [f"  condition: {' followed_by '.join(parts)}",
              f"  group_by: {det['group_by']}", f"  timeframe: {det['timeframe_min']}m",
              f"level: {rule['level']}", "tags:"] + [f"  - {t}" for t in rule["tags"]]
    return "\n".join(lines)


def render_unit_test(rule: dict) -> str:
    """The pytest file the Software Development agent writes alongside the rule."""
    name = rule["id"].lower().replace("-", "_")
    return f'''"""Auto-generated test for {rule['id']}."""
from core.paths import load_json
from tools.rules import rule_matches

RULE = {rule!r}


def test_{name}_fires_on_attack_replay():
    attack = load_json("attack_logs.json")["{rule['template']}"]
    assert rule_matches(RULE, attack)


def test_{name}_silent_on_benign():
    assert not rule_matches(RULE, load_json("benign_logs.json"))
'''
