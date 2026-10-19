"""Agentic features: LLM tool planning, fact-check loop, analyst memory, ingestion, Sigma, benchmark."""
from __future__ import annotations

import json

from agents.critic import fact_check, grounded_write
from agents.research import validate
from core import memory
from core.llm import MockLLM
from core.paths import DATA_DIR, load_json
from eval.benchmark import run_ablation, run_benchmark
from graph import GraphRunner, run
from tools.enrichment import threat_intel_lookup
from tools.ingest import load_alerts
from tools.sigma_export import to_sigma


def config(**extra):
    return {"data_dir": str(DATA_DIR), "mode": "mock", **extra}


class LazyPlanner(MockLLM):
    """An LLM that forgets to look up indicators: the Critic must catch it and send work back to Research."""

    def plan(self, kind, facts):
        p = super().plan(kind, facts)
        p["calls"] = [c for c in p["calls"] if c["tool"] != "threat_intel.lookup"]
        return p


class Hallucinator(MockLLM):
    """Invents an IP on the first attempt, fixes it when the Critic gives feedback."""

    def write(self, kind, facts, feedback=None):
        text = super().write(kind, facts)
        return text if feedback else text + " Seen from 203.0.113.9."


def test_persistent_fault_exhausts_retries_and_flags_for_human():
    state = run(load_json("alerts.json"), config(fault_mode="persistent"))
    assert state["retries"]["cp1"] == 2 and state["checkpoint_status"]["cp1"] == "flagged"
    flagged = [i for i in state["incidents"] if i.get("needs_human_review")]
    assert len(flagged) == 1
    attempts = [v["passed"] for v in state["critic_verdicts"] if v["checkpoint"] == 1 and v["incident_id"] == flagged[0]["id"]]
    assert attempts == [False, False, False]


def test_llm_plan_missing_lookups_is_sent_back_to_research(monkeypatch):
    monkeypatch.setattr("agents.research.get_llm", lambda cfg: LazyPlanner())
    state = run(load_json("alerts.json"), config())
    first = [v for v in state["critic_verdicts"] if v["checkpoint"] == 1 and v["attempt"] == 1 and not v["passed"]]
    assert first and all(v["target"] == "Research" for v in first)
    assert state["checkpoint_status"]["cp1"] == "pass"           # Research filled the gaps on the retry
    assert state["enriched_context"]["attempt"] == 2


def test_plan_validation_rejects_tools_and_foreign_arguments():
    facts = {"hosts": ["SRV-APP01"], "users": ["administrator"],
             "indicators": [{"value": "185.220.101.45"}]}
    ok, rejected = validate([{"tool": "assets.get", "arg": "SRV-APP01"}, {"tool": "assets.get", "arg": "SRV-DC01"},
                             {"tool": "rm -rf", "arg": "/"}, {"tool": "threat_intel.lookup", "arg": "185.220.101.45"}], facts)
    assert ok == [("assets.get", "SRV-APP01"), ("threat_intel.lookup", "185.220.101.45")]
    assert len(rejected) == 2


def test_fact_check_and_rewrite_loop():
    assert fact_check("INC-002 on SRV-APP01 scored 95", '{"id": "INC-002", "host": "SRV-APP01", "severity": 95}') == []
    assert fact_check("Traffic to 203.0.113.9 from SRV-DC01", '{"host": "SRV-APP01"}')
    text, record, _ = grounded_write(Hallucinator(), "handover", {"open": 3, "top": "P1 brute force"}, "handover", "test")
    assert "203.0.113.9" not in text and record["passed"] and record["attempts"] == 2


def test_analyst_memory_changes_the_next_run(tmp_path, monkeypatch):
    path = tmp_path / "memory.json"
    monkeypatch.setattr(memory, "MEMORY_PATH", path)
    alerts = load_json("alerts.json")
    first = run(alerts, config())
    target = next(i for i in first["incidents"] if i["route"] == "analyst_queue")   # chain C: off-hours transfer
    alerts_by_id = {a["id"]: a for a in first["alerts"]}
    learned = memory.learn(target, [alerts_by_id[a] for a in target["alert_ids"]], first["enriched_context"],
                           "false_positive", path=path)
    assert learned["allow"] and learned["baselines"]
    assert threat_intel_lookup(learned["allow"][0], memory=memory.load(path))["reputation"] == "benign"
    second = run(alerts, config(use_memory=True))
    again = next(i for i in second["incidents"] if set(i["alert_ids"]) == set(target["alert_ids"]))
    assert again["severity"] < target["severity"] and again["route"] == "auto_close"


def test_windows_sysmon_ingestion_finds_attacks():
    events = json.loads((DATA_DIR / "samples" / "windows_sysmon_sample.json").read_text())
    alerts, fmt = load_alerts(events, {h: v["ip"] for h, v in load_json("assets.json").items()})
    assert fmt == "windows" and len(alerts) > 15
    state = run(alerts, config())
    top = sorted(state["incidents"], key=lambda i: -i["severity"])
    assert top[0]["severity"] >= 90 and len(top[1]["hosts"]) == 3


def test_sigma_export_converts_with_pysigma():
    state = run(load_json("alerts.json"), config())
    bundle = next(b for b in state["detection_rule"].values() if b["rule"]["template"] == "brute_force")
    assert "correlation:" in bundle["sigma"]["sigma"] and "temporal_ordered" in bundle["sigma"]["sigma"]
    assert "EventID=4625" in bundle["sigma"]["splunk"] and bundle["sigma"]["elastic"]
    assert not bundle["sigma"]["errors"]


def test_graph_pauses_for_analyst_and_records_false_positive():
    runner = GraphRunner()
    nodes = [n for n, _, _ in runner.start(load_json("alerts.json"), config(require_approval=True))]
    assert nodes[-1] == "__interrupt__"
    ids = [r["incident_id"] for r in runner.pending["incidents"]]
    decisions = {iid: {"decision": "false_positive" if n == 0 else "approved", "by": "test", "comment": ""}
                 for n, iid in enumerate(ids)}
    assert [n for n, _, _ in runner.resume(decisions)] == ["approval", "automation"]
    assert runner.state["ticket"][ids[0]]["status"] == "Closed"
    assert runner.state["ticket"][ids[1]]["containment"].startswith("Approved")


def test_benchmark_and_ablation_smoke():
    bench = run_benchmark([3], [150])
    assert bench["summary"][0]["f1"][0] > 0.9
    abl = run_ablation(per_type=1)
    assert abl["total"]["caught"] == abl["total"]["injected"] == abl["total"]["shipped_without_critic"]
