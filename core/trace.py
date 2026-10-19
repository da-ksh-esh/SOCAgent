"""Trace logging. Every agent action and every tool call goes through a Tracer."""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Callable


def _short(value: Any, limit: int = 180) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        try:
            value = json.dumps(value, default=str)
        except TypeError:
            value = str(value)
    return value if len(value) <= limit else value[: limit - 1] + "…"


class Tracer:
    """Collects trace entries for one agent run; the node returns `tracer.entries`."""

    def __init__(self, agent: str):
        self.agent = agent
        self.entries: list[dict] = []

    def log(self, action: str, tool: str = "", inputs: Any = None, outputs: Any = None,
            status: str = "") -> None:
        self.entries.append({
            "agent": self.agent, "action": action, "tool": tool,
            "inputs": _short(inputs), "outputs": _short(outputs), "status": status,
            "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        })

    def call(self, tool: str, fn: Callable, *args, action: str = "", inputs: Any = None,
             show: Callable[[Any], Any] | None = None, **kwargs) -> Any:
        """Run a tool, log its inputs and (optionally summarised) output, return the result."""
        result = fn(*args, **kwargs)
        self.log(action or f"call {tool}", tool,
                 inputs if inputs is not None else (args or kwargs),
                 show(result) if show else result)
        return result
