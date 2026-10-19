"""Analyst memory: what analysts taught the system, applied on every later run.

- False positive  -> the incident's indicators are allow-listed (reputation becomes benign) and the
                     user's baseline learns the hours/hosts that looked anomalous.
- Confirmed       -> the incident's non-benign external indicators are block-listed (malicious).
Stored in memory/analyst_memory.json. Benchmark and tests run without memory.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from core.paths import ROOT
from tools.enrichment import indicators, is_external

MEMORY_PATH = ROOT / "memory" / "analyst_memory.json"
EMPTY = {"allow": {}, "block": {}, "baselines": {}, "log": []}


def load(path: Path | None = None) -> dict:
    path = path or MEMORY_PATH
    if not path.exists():
        return json.loads(json.dumps(EMPTY))
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return {**json.loads(json.dumps(EMPTY)), **data}
    except json.JSONDecodeError:
        return json.loads(json.dumps(EMPTY))


def save(memory: dict, path: Path | None = None) -> None:
    path = path or MEMORY_PATH
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(memory, indent=2), encoding="utf-8")


def _stamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def learn(incident: dict, alerts: list[dict], enriched: dict, verdict: str, by: str = "analyst",
          path: Path | None = None) -> dict:
    """Record an analyst verdict ('false_positive' or 'confirmed') and return what was learned."""
    memory = load(path)
    learned = {"allow": [], "block": [], "baselines": []}
    iocs = sorted({ioc for a in alerts for ioc in indicators(a)
                   if not (ioc.count(".") == 3 and not is_external(ioc))})   # skip internal IPs
    note = f"{verdict.replace('_', ' ')} on {incident['id']} ({incident['host']}) by {by}"
    if verdict == "false_positive":
        for ioc in iocs:
            memory["allow"][ioc] = {"note": note, "at": _stamp()}
            memory["block"].pop(ioc, None)
            learned["allow"].append(ioc)
        for a in alerts:
            for reason in enriched["alerts"].get(a["id"], {}).get("anomaly_reasons", []):
                b = memory["baselines"].setdefault(a["user"], {"extra_hosts": [], "extra_hours": []})
                hour = datetime.fromisoformat(a["ts"]).hour
                if "outside usual" in reason and hour not in b["extra_hours"]:
                    b["extra_hours"].append(hour)
                    learned["baselines"].append(f"{a['user']} active at {hour:02d}:00")
                if "unusual host" in reason and a["host"] not in b["extra_hosts"]:
                    b["extra_hosts"].append(a["host"])
                    learned["baselines"].append(f"{a['user']} uses {a['host']}")
    elif verdict == "confirmed":
        for ioc in iocs:
            rep = enriched.get("intel", {}).get(ioc, {}).get("reputation", "unknown")
            if rep != "benign":
                memory["block"][ioc] = {"note": note, "at": _stamp()}
                memory["allow"].pop(ioc, None)
                learned["block"].append(ioc)
    else:
        raise ValueError(f"unknown verdict {verdict}")
    memory["log"].append({"at": _stamp(), "incident": incident["id"], "verdict": verdict, "by": by, "learned": learned})
    save(memory, path)
    return learned


def forget(kind: str, key: str, path: Path | None = None) -> None:
    memory = load(path)
    memory.get(kind, {}).pop(key, None)
    save(memory, path)


def clear(path: Path | None = None) -> None:
    (path or MEMORY_PATH).unlink(missing_ok=True)
