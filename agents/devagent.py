"""5 Software Development agent: for severity >= 70, writes the IR playbook, a detection rule
and its unit test, runs the test on synthetic attack and benign logs, and exports the rule as
Sigma (converted to Splunk and Elastic queries with pySigma).

Decision: the rule template follows the correlated kill-chain stages. On a retry it reads the
Critic's reasons and regenerates the rule and playbook.
"""
from __future__ import annotations

from core import faults
from core.paths import load_json
from core.state import SOCState
from core.trace import Tracer
from tools.playbooks import build_playbook
from tools.rules import generate_rule, render_unit_test, render_yaml, run_rule_tests
from tools.sigma_export import to_sigma


def devagent_node(state: SOCState) -> dict:
    t = Tracer("Software Development")
    cfg = state["config"]
    attempt = state["retries"]["cp2"] + 1
    escalated = sorted([i for i in state["incidents"] if i["route"] == "escalate"], key=lambda i: -i["severity"])
    pick = lambda f: escalated[min(f["pick"], len(escalated) - 1)]["id"] if f and escalated else None
    broad_target = pick(faults.active(cfg, "broad_rule", attempt))
    unsafe_target = pick(faults.active(cfg, "unsafe_playbook", attempt))
    if attempt > 1:
        last = [v for v in state["critic_verdicts"] if v["checkpoint"] == 2 and not v["passed"]]
        t.log(f"attempt {attempt}: revising after Critic feedback", "", [v["incident_id"] for v in last],
              "; ".join(v["reasons"][0] for v in last))

    attack_logs = load_json("attack_logs.json", cfg["data_dir"])
    benign_logs = load_json("benign_logs.json", cfg["data_dir"])
    alerts_by_id = {a["id"]: a for a in state["alerts"]}
    rules = dict(state.get("detection_rule", {}))
    playbooks = dict(state.get("playbook", {}))
    for inc in escalated:
        own = [alerts_by_id[i] for i in inc["alert_ids"]]
        unsafe, broad = inc["id"] == unsafe_target, inc["id"] == broad_target
        playbooks[inc["id"]] = t.call("playbook_writer", build_playbook, inc, own, state["enriched_context"],
                                      unsafe=unsafe, action="write IR playbook", inputs=inc["id"],
                                      show=lambda p: f"{len(p)} steps: " + " > ".join(dict.fromkeys(s['phase'] for s in p)))
        rule = t.call("generate_rule", generate_rule, inc, broken=broad, action="generate detection rule",
                      inputs=f"{inc['id']} stages={inc['stages']}",
                      show=lambda r: f"{r['id']}: {len(r['detection']['steps'])} step(s), {r['template']}")
        if broad or unsafe:
            t.log("FAULT: " + " + ".join(x for x, on in (("over-broad rule", broad), ("unsafe playbook order", unsafe)) if on),
                  "fault_injector", inc["id"], "", status="fault")
        replay = attack_logs.get(rule["template"], own)
        tests = t.call("unit_test_runner", run_rule_tests, rule, replay, benign_logs, own,
                       action="run unit test on attack + benign logs", inputs=rule["id"],
                       show=lambda r: f"{r['tests_passed']}/{r['tests_total']} passed")
        sigma = t.call("pysigma.convert", to_sigma, rule, own, action="export Sigma + convert (Splunk, Elastic)",
                       inputs=rule["id"], show=lambda s: "ok" if not s["errors"] else s["errors"][0])
        rules[inc["id"]] = {"rule": rule, "yaml": render_yaml(rule), "unit_test": render_unit_test(rule),
                            "self_test": tests, "sigma": sigma, "attempt": attempt}
    t.log(f"attempt {attempt} complete", "", f"{len(escalated)} high-severity incidents",
          f"{len(escalated)} playbooks, {len(escalated)} rules submitted to Critic")
    return {"detection_rule": rules, "playbook": playbooks, "trace": t.entries}
