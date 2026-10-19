r"""LangGraph orchestration layer: task order, severity routing and Critic retry loops.

planner -> research -> executor -> critic_cp1 --(missing lookups)--> research -> executor ...
                                              |--(bad evidence/score)--> executor
                                              \--(pass/flagged)--> router
router --(any high)--> devagent -> critic_cp2 --(retry)--> devagent
      \                                       \--(pass/flagged)--> approval (analyst) -> automation
       \--(no high)--> automation -> END

The approval node can pause the graph (LangGraph interrupt); GraphRunner resumes it with the
analyst's decisions. A checkpointer keeps the paused state in memory between the two calls.
"""
from __future__ import annotations

from typing import Any, Iterator
from uuid import uuid4

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command

from agents.approval import approval_node
from agents.automation import automation_node
from agents.critic import critic_cp1_node, critic_cp2_node
from agents.devagent import devagent_node
from agents.executor import executor_node
from agents.planner import planner_node
from agents.research import research_node
from agents.router import router_node
from core.state import SOCState, initial_state

NODE_LABELS = {
    "planner": "1 Planner", "research": "2 Research", "executor": "3 Executor",
    "critic_cp1": "4 Critic · CP1", "router": "Severity router", "devagent": "5 Software Dev",
    "critic_cp2": "4 Critic · CP2", "approval": "Analyst approval",
    "automation": "6 Business Automation",
}


def after_cp1(state: SOCState) -> str:
    status = state["checkpoint_status"]
    if status.get("cp1") != "retry":
        return "router"
    return "research" if status.get("cp1_target") == "research" else "executor"


def after_router(state: SOCState) -> str:
    return "devagent" if any(i["route"] == "escalate" for i in state["incidents"]) else "automation"


def after_cp2(state: SOCState) -> str:
    return "devagent" if state["checkpoint_status"].get("cp2") == "retry" else "approval"


def build_graph(checkpointer=None):
    g = StateGraph(SOCState)
    g.add_node("planner", planner_node)
    g.add_node("research", research_node)
    g.add_node("executor", executor_node)
    g.add_node("critic_cp1", critic_cp1_node)
    g.add_node("router", router_node)
    g.add_node("devagent", devagent_node)
    g.add_node("critic_cp2", critic_cp2_node)
    g.add_node("approval", approval_node)
    g.add_node("automation", automation_node)

    g.add_edge(START, "planner")
    g.add_edge("planner", "research")
    g.add_edge("research", "executor")
    g.add_edge("executor", "critic_cp1")
    g.add_conditional_edges("critic_cp1", after_cp1, {"research": "research", "executor": "executor", "router": "router"})
    g.add_conditional_edges("router", after_router, {"devagent": "devagent", "automation": "automation"})
    g.add_edge("devagent", "critic_cp2")
    g.add_conditional_edges("critic_cp2", after_cp2, {"devagent": "devagent", "approval": "approval"})
    g.add_edge("approval", "automation")
    g.add_edge("automation", END)
    return g.compile(checkpointer=checkpointer)


APPEND_KEYS = {"trace", "critic_verdicts", "prose_checks"}


class GraphRunner:
    """Runs the graph, keeps the merged state, and can pause for and resume after analyst approval."""

    def __init__(self) -> None:
        self.graph = build_graph(checkpointer=InMemorySaver())
        self.thread = {"configurable": {"thread_id": uuid4().hex}, "recursion_limit": 50}
        self.state: dict[str, Any] = {}
        self.pending: dict | None = None   # interrupt payload while waiting for the analyst

    def _consume(self, graph_input) -> Iterator[tuple[str, dict, dict]]:
        self.pending = None
        for chunk in self.graph.stream(graph_input, self.thread, stream_mode="updates"):
            for node, update in chunk.items():
                if node == "__interrupt__":
                    self.pending = update[0].value
                    yield node, {}, self.state
                    continue
                for key, value in (update or {}).items():
                    self.state[key] = self.state.get(key, []) + value if key in APPEND_KEYS else value
                yield node, update or {}, self.state

    def start(self, alerts: list[dict], config: dict) -> Iterator[tuple[str, dict, dict]]:
        self.state = dict(initial_state(alerts, config))
        return self._consume(dict(self.state))

    def resume(self, decisions: dict) -> Iterator[tuple[str, dict, dict]]:
        return self._consume(Command(resume=decisions))


def stream_run(alerts: list[dict], config: dict) -> Iterator[tuple[str, dict, dict]]:
    """Yield (node, update, accumulated_state) after each node (no approval pause)."""
    yield from GraphRunner().start(alerts, {**config, "require_approval": False})


def run(alerts: list[dict], config: dict) -> dict:
    """Run the whole graph headless and return the final state."""
    final: dict = {}
    for _, _, final in stream_run(alerts, config):
        pass
    return final
