"""Core pipeline tests. Mock LLM only: no Ollama, no network."""
from __future__ import annotations

import copy

import pytest

from agents.critic import recompute_from_evidence
from agents.planner import group_alerts
from core import rubric
from core.paths import DATA_DIR, load_json
from eval.run_eval import evaluate
from graph import run
from tools.playbooks import check_playbook_order
from tools.rules import generate_rule, rule_matches


def config(**extra):
    return {"data_dir": str(DATA_DIR), "mode": "mock", **extra}


@pytest.fixture(scope="module")
def clean():
    return run(load_json("alerts.json"), config())


@pytest.fixture(scope="module")
def faulty():
    return run(load_json("alerts.json"), config(fault_mode="all"))


def incident_for(state, chain):
    ids = set(load_json("ground_truth.json")["chains"][chain]["alert_ids"])
    return max(state["incidents"], key=lambda i: len(ids & set(i["alert_ids"])))


def test_rubric_components_and_clamp():
    assert rubric.compute_severity(3, "crown_jewel", "malicious", "anomalous")["total"] == 100
    assert rubric.compute_severity(4, "low", "unknown", "normal")["stage_points"] == 45
    assert rubric.compute_severity(0, "low", "benign", "normal")["total"] == 0


@pytest.mark.parametrize("score,route", [(39, "auto_close"), (40, "analyst_queue"), (69, "analyst_queue"), (70, "escalate")])
def test_routing_thresholds(score, route):
    assert rubric.route_for(score) == route


def test_grouping_splits_on_time_gap():
    alerts = [{"id": "1", "host": "H", "ts": "2026-10-14T10:00:00"}, {"id": "2", "host": "H", "ts": "2026-10-14T10:20:00"},
              {"id": "3", "host": "H", "ts": "2026-10-14T11:30:00"}]
    assert [[a["id"] for a in g] for g in group_alerts(alerts, 30)] == [["1", "2"], ["3"]]


def test_all_four_attacks_correlated_and_noise_low(clean):
    result = evaluate(clean, load_json("ground_truth.json"))
    assert result["attacks_correlated"] == 4
    assert result["benign_wrongly_escalated"] == 0
    assert result["alerts"]["f1"] == 1.0


def test_lateral_movement_is_linked_across_hosts(clean):
    inc = incident_for(clean, "D")
    assert len(inc["hosts"]) == 3 and "lateral_movement" in inc["stages"]
    assert "T1021.002" in {t["id"] for t in inc["techniques"]}


def test_critic_rejects_claim_without_evidence(clean):
    alerts_by_id = {a["id"]: a for a in clean["alerts"]}
    top = copy.deepcopy(max(clean["incidents"], key=lambda i: i["severity"]))
    parts, problems = recompute_from_evidence(top, alerts_by_id, clean["enriched_context"])
    assert not problems and parts["total"] == top["severity"]
    top["claims"][0]["alert_ids"] = []
    parts, problems = recompute_from_evidence(top, alerts_by_id, clean["enriched_context"])
    assert problems and parts["total"] < top["severity"]


def test_clean_run_has_no_retries(clean):
    assert clean["retries"] == {"cp1": 0, "cp2": 0}
    assert all(p["passed"] and p["attempts"] == 1 for p in clean["prose_checks"])


def test_all_faults_loop_back_then_pass(faulty):
    assert faulty["retries"] == {"cp1": 1, "cp2": 1}
    assert faulty["checkpoint_status"]["cp1"] == "pass" and faulty["checkpoint_status"]["cp2"] == "pass"
    failed = [v for v in faulty["critic_verdicts"] if not v["passed"]]
    assert {v["target"] for v in failed} == {"Research", "Executor", "Software Development"}
    rewritten = [p for p in faulty["prose_checks"] if p["rejections"]]
    assert rewritten and all(p["passed"] for p in rewritten)


def test_rules_fire_on_attack_and_stay_silent_on_benign(clean):
    attack, benign = load_json("attack_logs.json"), load_json("benign_logs.json")
    templates = set()
    for inc in [i for i in clean["incidents"] if i["route"] == "escalate"]:
        rule = generate_rule(inc)
        templates.add(rule["template"])
        assert rule_matches(rule, attack[rule["template"]])
        assert not rule_matches(rule, benign)
        assert rule_matches(generate_rule(inc, broken=True), benign)
    assert templates == {"brute_force", "phishing_c2", "lateral_movement"}


def test_playbook_order_rules(clean):
    for steps in clean["playbook"].values():
        assert check_playbook_order(steps) == []
    bad = [{"order": 1, "phase": "contain", "action": "isolate", "owner": "EDR"},
           {"order": 2, "phase": "preserve_evidence", "action": "snapshot", "owner": "DFIR"},
           {"order": 3, "phase": "eradicate", "action": "x", "owner": "x"},
           {"order": 4, "phase": "recover", "action": "x", "owner": "x"}]
    assert check_playbook_order(bad)
