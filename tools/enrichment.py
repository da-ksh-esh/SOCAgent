"""Enrichment tools the Research agent can call (and the Critic re-uses).

threat_intel.lookup, assets.get, users.baseline and hunt.indicator read local data only: no network.
Analyst memory (core/memory.py) overrides the feed and baselines when it is passed in.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime

from core.paths import DATA_DIR, load_json

INTEL_ORDER = ["malicious", "suspicious", "benign", "unknown"]  # first match wins


def indicators(alert: dict) -> list[str]:
    """IPs, domain and hash carried by an alert."""
    return [alert[k] for k in ("src_ip", "dst_ip", "domain", "hash") if alert.get(k)]


def is_external(ip: str) -> bool:
    try:
        return not ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def threat_intel_lookup(indicator: str, data_dir=DATA_DIR, memory: dict | None = None) -> dict:
    """Reputation for an IP, domain or hash; 'unknown' when the feed has no entry."""
    if memory:
        if indicator in memory.get("allow", {}):
            return {"indicator": indicator, "reputation": "benign", "source": "analyst memory",
                    "note": "Allow-listed: " + memory["allow"][indicator]["note"]}
        if indicator in memory.get("block", {}):
            return {"indicator": indicator, "reputation": "malicious", "source": "analyst memory",
                    "note": "Block-listed: " + memory["block"][indicator]["note"]}
    entry = load_json("threat_intel.json", data_dir).get(indicator)
    return {"indicator": indicator, "reputation": entry["reputation"] if entry else "unknown",
            "note": entry["note"] if entry else "", "source": "threat feed"}


def asset_get(host: str, data_dir=DATA_DIR) -> dict:
    entry = load_json("assets.json", data_dir).get(host)
    return {"host": host, **entry} if entry else {"host": host, "owner": "unknown", "role": "unknown",
                                                  "criticality": "medium", "ip": ""}


def user_baseline(user: str, data_dir=DATA_DIR, memory: dict | None = None) -> dict | None:
    entry = load_json("user_baselines.json", data_dir).get(user)
    if not entry:
        return None
    base = {"user": user, **entry, "learned": []}
    learned = (memory or {}).get("baselines", {}).get(user)
    if learned:
        base["usual_hosts"] = sorted(set(base["usual_hosts"]) | set(learned.get("extra_hosts", [])))
        base["extra_hours"] = sorted(learned.get("extra_hours", []))
        base["learned"] = [f"host {h}" for h in learned.get("extra_hosts", [])] + \
                          [f"{h:02d}:00" for h in learned.get("extra_hours", [])]
    return base


def hunt_indicator(indicator: str, alerts: list[dict]) -> dict:
    """Search every alert in the batch for an indicator: where else has it been seen?"""
    hits = [a for a in alerts if indicator in indicators(a)]
    return {"indicator": indicator, "alerts": len(hits), "hosts": sorted({a["host"] for a in hits}),
            "users": sorted({a["user"] for a in hits if a["user"]})}


def anomaly_reasons(alert: dict, baseline: dict | None) -> list[str]:
    """Why an alert deviates from the user's baseline (empty list = normal)."""
    if not alert.get("user"):
        return []
    if baseline is None:
        return [f"no baseline for user '{alert['user']}'"]
    reasons = []
    hour = datetime.fromisoformat(alert["ts"]).hour
    start, end = baseline["work_hours"]
    if not start <= hour < end and hour not in baseline.get("extra_hours", []):
        reasons.append(f"{alert['user']} active at {hour:02d}:00, outside usual {start:02d}-{end:02d}h")
    if alert["host"] not in baseline["usual_hosts"]:
        reasons.append(f"{alert['user']} on unusual host {alert['host']}")
    return reasons


def worst_verdict(reputations: list[str]) -> str:
    """Incident-level intel verdict: the most severe known reputation wins."""
    for verdict in INTEL_ORDER:
        if verdict in reputations:
            return verdict
    return "unknown"


def required_lookups(alerts: list[dict]) -> set[tuple[str, str]]:
    """Every lookup needed to judge these alerts: each indicator, host and user."""
    need = set()
    for a in alerts:
        need |= {("threat_intel.lookup", ioc) for ioc in indicators(a)}
        need.add(("assets.get", a["host"]))
        if a["user"]:
            need.add(("users.baseline", a["user"]))
    return need
