"""Fault injection: deliberately wrong agent work, used to prove the Critic catches it.

Each fault hits one agent's first attempt (or every attempt when persistent):
  skip_lookup      Research   omits a threat-intel lookup the incident needs
  drop_evidence    Executor   a stage claim loses its cited alert IDs
  inflate_score    Executor   severity is raised without evidence
  fake_stage       Executor   claims a kill-chain stage the alerts do not support
  hallucinate      Executor   the LLM summary mentions an IP that is not in the facts
  broad_rule       Software   detection rule is over-broad (fires on benign logs)
  unsafe_playbook  Software   playbook isolates the host before evidence is preserved

`pick` selects the target: 0 = the most severe incident (or most suspicious candidate), 1 = next...
"""
from __future__ import annotations

FAULT_TYPES = ["skip_lookup", "drop_evidence", "inflate_score", "fake_stage", "hallucinate",
               "broad_rule", "unsafe_playbook"]
FAULT_AGENT = {"skip_lookup": "Research", "drop_evidence": "Executor", "inflate_score": "Executor",
               "fake_stage": "Executor", "hallucinate": "Executor", "broad_rule": "Software Development",
               "unsafe_playbook": "Software Development"}
DEMO_MODES = {
    "all": ["skip_lookup", "drop_evidence", "hallucinate", "broad_rule", "unsafe_playbook"],
    "persistent": ["drop_evidence"],
}
HALLUCINATED_IP = "198.51.100.23"


def fault_plan(config: dict) -> list[dict]:
    if config.get("faults") is not None:
        return config["faults"]
    mode = config.get("fault_mode")
    if mode not in DEMO_MODES:
        return []
    return [{"type": t, "pick": 0, "persistent": mode == "persistent"} for t in DEMO_MODES[mode]]


def active(config: dict, fault_type: str, attempt: int) -> dict | None:
    """The fault to apply on this attempt, if any."""
    for f in fault_plan(config):
        if f["type"] == fault_type and (attempt == 1 or f.get("persistent")):
            return f
    return None
