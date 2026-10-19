# CLAUDE.md: Multi-Agent SOC Alert Triage and Incident Response Assistant

## What this project is

A course project (CA-3, Agentic AI Proof of Concept, SIT Pune, pair of two students). Six cooperating
agents turn a batch of security alerts into prioritised, evidence-backed incidents, a response playbook, a
tested detection rule (exported as Sigma), a ticket and a report. A Critic validates the work and sends it
back; an analyst approves containment; analyst verdicts are remembered across runs.

Domain: Cybersecurity Operations (Security Operations Centre).

The assignment says a plain chatbot is not enough. The PoC must visibly show **task planning, tool
execution, decision-making, validation and agent collaboration**. Everything runs on dummy data with no paid API.

## Status (18 Oct)

- Done: problem statement, architecture diagram, 9-slide deck (submitted 15 Oct).
- Built: web console (`server.py` + `web/`), six agents, LangGraph with severity routing, Critic loops back to
  Research / Executor / Software Development, LLM fact-check loop, analyst approval (LangGraph interrupt),
  analyst memory, cross-host correlation, Windows/Sysmon ingestion, pySigma export, live alert feed,
  benchmark + Critic ablation, grounded Q&A chat. 28 pytest tests.
- Removed on 18 Oct (decided with the user): the Streamlit UI, run history, the "analyst time saved"
  estimate (invented numbers), the hard-coded ransomware scenario, the entity graph, playback speed,
  CP1-only/CP2-only fault modes, markdown/CSV exports.
- Latest results (`python eval/run_eval.py`): demo dataset 4/4 chains, 0/127 benign escalated, F1 1.0;
  benchmark 57/60 chains over 15 datasets (the misses are one seed where phishing hits a low-criticality
  host and scores 65 instead of high); ablation 42/42 injected faults caught and corrected with the Critic,
  42/42 shipped with the Critic disabled.
- **Presentations and demos run 19 to 22 Oct 2026, 5 minutes per pair.**

## Hard constraints

- Python, LangGraph, free and local only. No paid APIs. (The course brief said Streamlit; the team chose a
  FastAPI + plain HTML/JS console instead.)
- The console uses **local Ollama only**: no silent fallback, a run stops with a clear error if Ollama fails.
- **Scoring, routing and every pass/fail decision are deterministic Python.** The LLM may (a) plan which
  enrichment tools to call — validated against the candidate's own entities and audited by the Critic for
  completeness — and (b) write prose, which the Critic fact-checks.
- MockLLM exists only for pytest and the benchmark, which must not need Ollama or a network.
- All data is synthetic or a hand-written sample in a public log format. All integrations are mocks.
- Both students must be able to explain every part. Keep the code simple and readable over clever.

## Architecture

```
alerts (synthetic | Windows/Sysmon | upload)
  -> 1 Planner        group by host + 30-min window -> candidates (task_plan)
  -> 2 Research       LLM plans tools per suspicious candidate; checklist for quiet ones; runs lookups
  -> 3 Executor       link candidates across hosts; kill-chain stages; rubric score; LLM summary (fact-checked)
  -> 4 Critic CP1     missing lookups -> back to Research
                      bad evidence / score mismatch -> back to Executor     (max 2 retries, then human review)
  -> severity router  <40 auto-close | 40-69 analyst queue | >=70 Software Development
  -> 5 Software Dev   playbook + detection rule + unit test + Sigma (pySigma -> Splunk, Elastic)
  -> 4 Critic CP2     rule fires on attacks, silent on benign; playbook preserves evidence first -> else back
  -> Analyst          LangGraph interrupt: approve / hold / false positive (approve + FP update memory)
  -> 6 Automation     tickets, SLA, mock notifications, report + handover (LLM prose, fact-checked)
```

The diagram is `docs/architecture.png`, rendered from `docs/architecture.svg` (edit the SVG, then re-render).

## Where things live

```
server.py               FastAPI: runs (SSE events), approval, feedback, memory, datasets, feed, benchmark, exports
web/                    index.html, app.css, app.js (no build step)
graph.py                LangGraph definition, routing, retry edges, GraphRunner (pause/resume)
agents/                 planner research executor critic router devagent approval automation
core/                   state rubric llm (MockLLM + OllamaLLM) trace faults memory qa exports paths
tools/                  enrichment (intel/assets/baselines/hunt) correlate (stages + cross-host link) mitre
                        rules (generator + tester) sigma_export playbooks ticketing ingest (Windows/Sysmon)
scripts/generate_data.py  seeded generator: --seed, --alerts; also writes data/samples/windows_sysmon_sample.json
eval/                   run_eval.py (ground-truth metrics), benchmark.py (multi-seed + ablation)
tests/                  pipeline, features, qa
memory/                 analyst_memory.json (runtime, not committed)
```

## Severity rubric (`core/rubric.py`)

```
severity = min(100, stage_points + asset_points + intel_points + behaviour_points), floor 0
stage_points     = 15 x distinct kill-chain stages (max 45)
asset_points     = low 0 | medium 10 | high 20 | crown_jewel 25   (multi-host: the most critical host)
intel_points     = malicious 20 | suspicious 10 | unknown 0 | benign -10
behaviour_points = anomalous vs user baseline 10 | normal 0
```

The Executor computes it; the Critic recomputes it from the cited evidence only and compares, without
reading the Executor's number first.

## Faults (`core/faults.py`)

skip_lookup (Research), drop_evidence / inflate_score / fake_stage / hallucinate (Executor),
broad_rule / unsafe_playbook (Software Development). Console modes: "Critic loops" (one of several types,
first attempt only) and "Persistent" (drop_evidence on every attempt). `config["critic_enabled"] = False`
keeps the checks but never sends work back (used by the ablation).

## Conventions

- Type hints, small functions, docstrings that say what the agent decides and why.
- Every tool call goes through `core/trace.Tracer` so it shows in the live trace.
- No hard-coded absolute paths; seeded data generation.
- `pytest` must pass without Ollama or a network.
- Run: `pip install -r requirements.txt`, `ollama pull llama3.2`, `python scripts/generate_data.py`, `python server.py`.

## Pair split

- Person A: data generation, ingestion, Planner, Research, Executor, rubric, correlation.
- Person B: Critic (incl. fact-check), Software Development + Sigma, approval/memory, Business Automation, web console.
- Both: graph wiring, evaluation/benchmark, and a swap review so each can explain the whole system in Q&A.

## Not in scope

Real SIEM integrations, real threat-intel feeds, real containment actions, authentication, deployment.
