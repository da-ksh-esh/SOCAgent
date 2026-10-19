"""LLM clients.

The consoles use OllamaLLM (local Ollama only). MockLLM is deterministic and exists so pytest and
the benchmark run without a model. Both expose the same interface:

  write(kind, facts, feedback=None) -> str   prose (summaries, reports, chat answers)
  plan(kind, facts) -> dict                   a JSON decision, e.g. which enrichment tools to call

Whatever the model returns is checked by plain Python before it is used: tool calls are validated
against the candidate's own entities, and prose is fact-checked by the Critic.
"""
from __future__ import annotations

import json
import os
import re
import urllib.request
from typing import Any


def _ollama_host() -> str:
    """Ollama's address: the OLLAMA_HOST environment variable (Ollama's own convention) or the default."""
    host = os.environ.get("OLLAMA_HOST", "").strip() or "localhost:11434"
    host = host.replace("0.0.0.0", "localhost")
    if ":" not in host.split("//")[-1]:
        host += ":11434"
    return host if host.startswith("http") else "http://" + host


OLLAMA_HOST = _ollama_host()
DEFAULT_MODEL = "llama3.2"

STAGE_WORDS = {
    "reconnaissance": "reconnaissance (scanning)",
    "delivery": "delivery (phishing link)",
    "credential_access": "credential access (password guessing or dumping)",
    "initial_access": "initial access (successful login)",
    "execution": "execution (malicious file or remote service)",
    "persistence": "persistence (new admin account)",
    "lateral_movement": "lateral movement (remote logons between hosts)",
    "command_and_control": "command and control (beaconing)",
    "exfiltration": "exfiltration (bulk data transfer)",
    "impact": "impact (encryption)",
}


def _stages_text(stages: list[str]) -> str:
    return ", then ".join(STAGE_WORDS.get(s, s) for s in stages) or "no kill-chain stage"


class MockLLM:
    """Deterministic templates (tests and benchmark only)."""

    name = "mock"

    def write(self, kind: str, facts: dict[str, Any], feedback: str | None = None) -> str:
        f = facts
        if kind == "incident_summary":
            return (f"{f['id']} on {f['host']} ({f['asset']} asset): {_stages_text(f['stages'])}. "
                    f"Threat intel verdict is {f['intel']}; user behaviour is {f['behaviour']}. "
                    f"Severity {f['severity']}/100 ({f['label']}).")
        if kind == "auto_close_note":
            reason = f.get("reason") or "activity matches known benign patterns"
            return (f"Auto-closed {f['id']} (severity {f['severity']}): {reason}. "
                    f"Evidence: {', '.join(f['alert_ids'][:4])}{'…' if len(f['alert_ids']) > 4 else ''}. "
                    "No analyst time required.")
        if kind == "report_narrative":
            return (f"During this run the assistant triaged {f['alerts']} alerts into {f['incidents']} "
                    f"candidate incidents. {f['high']} were escalated with a playbook and detection rule, "
                    f"{f['medium']} were queued for an analyst and {f['low']} were auto-closed with a "
                    f"justification note. The Critic sent work back {f['retries']} time(s) before approving it.")
        if kind == "handover":
            return (f"Shift handover: {f['open']} open ticket(s). Highest priority is {f['top']}. "
                    "Check SLA timers before the next shift starts; all containment actions "
                    "in this PoC are simulated and need a human to execute them.")
        if kind == "qa_answer":
            facts_list = f["facts"]
            if not facts_list:
                return "I could not find anything in this run that answers that."
            lead = {"off_topic": "I can only answer questions about this triage run. Here is its overview:",
                    "critic": "Here is what the Critic decided:", "playbook": "Here is the response plan:",
                    "rule": "Here is the detection rule:", "ticket": "Here is the ticket status:",
                    "attack": "Here is the ATT&CK mapping:", "closed": "Here is why these were closed:",
                    "approval": "Here are the analyst decisions:", "memory": "Here is what analysts taught the system:",
                    "research": "Here is how the Research agent investigated:", "factcheck": "Here is what the fact-check found:",
                    "score": "Here is how the score was built:"}
            topics = f.get("topics", [])
            first = next((lead[t] for t in lead if t in topics), "Here is what this run shows:")
            return first + "\n" + "\n".join(f"- {line}" for line in facts_list[:14])
        if kind == "incident_report":
            return (f"{f['id']} was detected on {', '.join(f['hosts'])} between {f['start']} and {f['end']}. "
                    f"The attacker progressed through {_stages_text(f['stages'])}. "
                    f"The incident scored {f['severity']}/100 and was routed to {f['route']}.")
        return json.dumps(facts, default=str)

    def plan(self, kind: str, facts: dict[str, Any]) -> dict:
        if kind == "investigation":
            calls = [{"tool": "assets.get", "arg": h} for h in facts["hosts"]]
            calls += [{"tool": "users.baseline", "arg": u} for u in facts["users"]]
            calls += [{"tool": "threat_intel.lookup", "arg": i["value"]} for i in facts["indicators"]]
            calls += [{"tool": "hunt.indicator", "arg": i["value"]} for i in facts["indicators"] if i["external"]]
            return {"calls": calls, "rationale": "Checklist plan: every host, user and indicator; hunt external ones."}
        raise ValueError(kind)


class OllamaError(RuntimeError):
    """Raised by a strict OllamaLLM when the model cannot answer."""


class OllamaLLM:
    """Local Ollama backend.

    strict=True (the console): any Ollama failure raises OllamaError, so a run never silently
    switches to template wording. Only REWRITE_KINDS go to the model for prose; the ~40 auto-close
    notes are plain string formatting of the facts so a run on a CPU-only laptop stays fast.
    """

    name = "ollama"
    REWRITE_KINDS = {"incident_summary", "incident_report", "report_narrative", "handover", "qa_answer"}

    def __init__(self, model: str = DEFAULT_MODEL, host: str = OLLAMA_HOST, timeout: float = 120,
                 strict: bool = False):
        self.model, self.host, self.timeout, self.strict = model, host, timeout, strict
        self.fallback = MockLLM()
        self.last_backend = "ollama"
        self.calls = 0
        self.failures = 0

    # ---------------------------------------------------------------- transport
    def _generate(self, prompt: str, json_mode: bool = False, max_tokens: int = 400) -> str:
        body = {"model": self.model, "prompt": prompt, "stream": False, "keep_alive": "30m",
                "options": {"temperature": 0, "num_predict": max_tokens}}
        if json_mode:
            body["format"] = "json"
        req = urllib.request.Request(f"{self.host}/api/generate", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
        self.calls += 1
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read())["response"]

    def _fail(self, exc: Exception) -> None:
        self.failures += 1
        if self.strict:
            raise OllamaError(f"Ollama model '{self.model}' did not answer ({type(exc).__name__}: {exc}). "
                              "Is Ollama running and the model pulled?") from exc
        self.last_backend = "template (Ollama unreachable)"

    # ---------------------------------------------------------------- prose
    def _prompt(self, kind: str, facts: dict[str, Any], draft: str, feedback: str | None) -> str:
        fix = (f"\nA reviewer REJECTED your previous attempt: {feedback}\nWrite it again using ONLY the facts.\n"
               if feedback else "")
        if kind == "qa_answer":
            return ("You are a SOC analyst assistant answering a question about one triage run.\n"
                    "Rules:\n"
                    "- Answer ONLY from the facts below. Every fact is true; never contradict or omit a "
                    "fact that answers the question (for example, list every REJECTED verdict).\n"
                    "- Cite incident IDs (INC-...) and alert IDs (ALT-...) exactly as written. Never invent "
                    "an ID, IP address, domain, host or number that is not in the facts.\n"
                    "- Playbook and containment steps are proposed, simulated actions: never say they were "
                    "executed or that an incident is contained.\n"
                    "- If the facts do not answer the question, say so.\n"
                    "- Be concise: at most 6 sentences or bullet points. No preamble.\n" + fix +
                    f"\nQuestion: {facts['question']}\n\nFacts:\n" + "\n".join(f"- {x}" for x in facts["facts"]))
        return (f"You are a SOC analyst assistant. Rewrite this {kind.replace('_', ' ')} in 2-3 clear, "
                "factual sentences. Do not add facts, IDs, IP addresses, hosts or numbers that are not given. "
                "Output only the rewritten text, with no introduction or heading." + fix +
                f"\nFacts: {json.dumps(facts, default=str)}\nDraft: {draft}")

    @staticmethod
    def _clean(text: str) -> str:
        """Drop chatty preambles small models add ("Here is a rewritten version ...:")."""
        lines = text.strip().splitlines()
        while lines and (not lines[0].strip() or
                         (lines[0].lower().startswith(("here is", "here's", "sure")) and lines[0].rstrip().endswith(":"))):
            lines.pop(0)
        # "•" bullets are not Markdown; turn them into list items so they render one per line.
        lines = [re.sub(r"^(\s*)[•●▪]\s*", r"\1- ", line) for line in lines]
        return "\n".join(lines).strip()

    def write(self, kind: str, facts: dict[str, Any], feedback: str | None = None) -> str:
        draft = self.fallback.write(kind, facts)
        if kind not in self.REWRITE_KINDS:
            self.last_backend = "template (no model)"
            return draft
        try:
            text = self._clean(self._generate(self._prompt(kind, facts, draft, feedback)))
            self.last_backend = f"ollama ({self.model})"
            return text or draft
        except Exception as exc:
            self._fail(exc)
            return draft

    # ---------------------------------------------------------------- decisions
    def plan(self, kind: str, facts: dict[str, Any]) -> dict:
        if kind != "investigation":
            raise ValueError(kind)
        inds = "\n".join(f"- {i['value']} ({i['type']}, {'external' if i['external'] else 'internal'}, "
                         f"seen in: {', '.join(i['rules'])})" for i in facts["indicators"]) or "- none"
        prompt = (
            "You are the Research agent in a SOC. Decide which enrichment tools to call before this "
            "candidate incident is scored. Be thorough: missing context leads to wrong severity.\n\n"
            "Tools:\n"
            "- threat_intel.lookup(arg=indicator): reputation of an IP, domain or file hash\n"
            "- assets.get(arg=host): owner and criticality of a host\n"
            "- users.baseline(arg=user): the user's usual hosts and working hours\n"
            "- hunt.indicator(arg=indicator): where else this indicator appears across all hosts\n\n"
            f"Candidate {facts['candidate']} ({facts['window']}):\n"
            f"Hosts: {', '.join(facts['hosts'])}\nUsers: {', '.join(facts['users']) or 'none'}\n"
            f"Alert rules: {', '.join(f'{r} x{n}' for r, n in facts['rules'].items())}\n"
            f"Indicators:\n{inds}\n\n"
            'Reply with JSON only: {"calls": [{"tool": "<tool name>", "arg": "<exact value from above>"}], '
            '"rationale": "<one sentence>"}')
        try:
            data = json.loads(self._generate(prompt, json_mode=True, max_tokens=500))
            self.last_backend = f"ollama ({self.model})"
            calls = data.get("calls", []) if isinstance(data, dict) else []
            return {"calls": [c for c in calls if isinstance(c, dict)], "rationale": str(data.get("rationale", ""))[:300]}
        except Exception as exc:
            self._fail(exc)
            return self.fallback.plan(kind, facts)


def warm_up(model: str, host: str = OLLAMA_HOST) -> None:
    """Load the model into memory so the first real call is not slow (keeps it loaded for 30 min)."""
    body = json.dumps({"model": model, "prompt": "ok", "stream": False, "keep_alive": "30m",
                       "options": {"num_predict": 1}}).encode()
    req = urllib.request.Request(f"{host}/api/generate", data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=180):
            pass
    except Exception:
        pass


def ollama_available(host: str = OLLAMA_HOST) -> bool:
    try:
        with urllib.request.urlopen(f"{host}/api/tags", timeout=1):
            return True
    except Exception:
        return False


def ollama_models(host: str = OLLAMA_HOST) -> list[str]:
    """Models pulled into the local Ollama server (empty if it is not running)."""
    try:
        with urllib.request.urlopen(f"{host}/api/tags", timeout=1) as resp:
            models = json.loads(resp.read()).get("models", [])
    except Exception:
        return []
    # Embedding-only models cannot write text; the recommended model goes first.
    names = [m["name"] for m in models if "completion" in m.get("capabilities", ["completion"])
             and "embed" not in m["name"]]
    return sorted(names, key=lambda n: n.split(":")[0] != DEFAULT_MODEL)


def get_llm(config: dict[str, Any]):
    if config.get("mode") == "ollama":
        return OllamaLLM(model=config.get("ollama_model", DEFAULT_MODEL), strict=config.get("strict", False))
    return MockLLM()
