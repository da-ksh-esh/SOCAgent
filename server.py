"""Web console backend: serves web/ and exposes the agent graph over a small JSON + SSE API.

Run: python server.py   then open http://localhost:8000  (SOC_HOST / SOC_PORT change the address)

Each run executes the LangGraph (graph.GraphRunner) in a background thread; every finished node
becomes an event the browser receives over Server-Sent Events. The consoles use local Ollama only.
"""
from __future__ import annotations

import asyncio
import json
import os
import threading
import uuid
from datetime import datetime

from fastapi import Body, FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from agents.planner import group_alerts
from core import memory, rubric
from core.exports import markdown_to_pdf, tickets_json
from core.faults import DEMO_MODES
from core.llm import get_llm, ollama_models, warm_up
from core.paths import DATA_DIR, ROOT, load_json
from core.qa import answer
from eval.run_eval import evaluate
from graph import NODE_LABELS, GraphRunner
from tools.correlate import detect_stages
from tools.ingest import load_alerts
from tools.mitre import TACTIC_ORDER, catalogue

WEB = ROOT / "web"
app = FastAPI(title="SOC Agent Console")
RUNS: dict[str, "Run"] = {}
UPLOADS: dict[str, dict] = {}
JOBS: dict[str, dict] = {}
TERMINAL = {"interrupt", "done", "error"}
FAULT_LABELS = {"all": "Critic loops: every checkpoint rejects once, then passes",
                "persistent": "Persistent error: retries exhausted, human review"}


@app.middleware("http")
async def no_cache_assets(request, call_next):
    """Always revalidate the page and its JS/CSS so edits show up without a hard refresh."""
    response = await call_next(request)
    if request.url.path == "/" or request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-cache"
    return response


# ------------------------------------------------------------------ datasets

def host_ips() -> dict[str, str]:
    return {h: v.get("ip", "") for h, v in load_json("assets.json").items()}


def dataset_alerts(name: str) -> tuple[list[dict], str]:
    """(alerts, description) for a dataset key: synthetic | windows_sample | upload:<id>."""
    if name == "synthetic":
        return [dict(a) for a in load_json("alerts.json")], f"Synthetic SIEM alerts (seed {load_json('ground_truth.json').get('seed', '?')})"
    if name == "windows_sample":
        events = json.loads((DATA_DIR / "samples" / "windows_sysmon_sample.json").read_text(encoding="utf-8"))
        return load_alerts(events, host_ips())[0], "Windows Security + Sysmon sample"
    if name.startswith("upload:") and name[7:] in UPLOADS:
        up = UPLOADS[name[7:]]
        return [dict(a) for a in up["alerts"]], up["label"]
    raise HTTPException(404, f"unknown dataset {name}")


def datasets() -> list[dict]:
    out = [{"key": "synthetic", "label": "Synthetic SIEM alerts", "alerts": len(load_json("alerts.json")), "eval": True},
           {"key": "windows_sample", "label": "Windows + Sysmon sample", "alerts": len(dataset_alerts("windows_sample")[0]),
            "eval": False}]
    out += [{"key": f"upload:{k}", "label": v["label"], "alerts": len(v["alerts"]), "eval": False} for k, v in UPLOADS.items()]
    return out


# ------------------------------------------------------------------ runs

class Run:
    """One graph execution: background thread in, list of events out."""

    def __init__(self, config: dict, alerts: list[dict], dataset: str):
        self.id = uuid.uuid4().hex[:10]
        self.config, self.alerts, self.dataset = config, alerts, dataset
        self.runner = GraphRunner()
        self.events: list[dict] = []
        self.path: list[tuple[str, str]] = []
        self.status = "running"

    def _consume(self, stream) -> None:
        try:
            for node, update, state in stream:
                if node == "__interrupt__":
                    self.status = "awaiting_approval"
                    self.events.append({"type": "interrupt", "payload": self.runner.pending})
                    return
                status = "done"
                if node.startswith("critic"):
                    cps = state["checkpoint_status"]
                    status = cps.get("cp1" if node == "critic_cp1" else "cp2", "pass")
                    if node == "critic_cp1" and status == "retry":
                        status = f"retry_{cps.get('cp1_target', 'executor')}"
                self.path.append((node, status))
                self.events.append({
                    "type": "node", "node": node, "label": NODE_LABELS[node], "status": status,
                    "trace": update.get("trace", []), "retries": state.get("retries", {}),
                    "verdicts": [v for v in update.get("critic_verdicts", []) if not v["passed"]][:4],
                    "prose": [p for p in update.get("prose_checks", []) if p["rejections"]][:4],
                })
            self.status = "done"
            self.events.append({"type": "done"})
        except Exception as exc:  # surface failures to the browser instead of hanging
            self.status = "error"
            self.events.append({"type": "error", "message": f"{type(exc).__name__}: {exc}"})

    def start(self) -> None:
        threading.Thread(target=self._consume, args=(self.runner.start(self.alerts, self.config),), daemon=True).start()

    def resume(self, decisions: dict) -> None:
        self.status = "running"
        threading.Thread(target=self._consume, args=(self.runner.resume(decisions),), daemon=True).start()


def get_run(run_id: str, done: bool = False) -> Run:
    if run_id not in RUNS:
        raise HTTPException(404, "unknown run")
    run = RUNS[run_id]
    if done and run.status != "done":
        raise HTTPException(409, f"run is {run.status}")
    return run


def ollama_config(model: str | None) -> dict:
    """The console uses Ollama only. Refuse to run rather than fall back to template wording."""
    models = ollama_models()
    if not models:
        raise HTTPException(503, "Ollama is not running or has no models. Start Ollama and run `ollama pull llama3.2`.")
    if model and model not in models:
        raise HTTPException(400, f"Model '{model}' is not pulled. Available: {', '.join(models)}")
    return {"mode": "ollama", "ollama_model": model or models[0], "strict": True}


class RunRequest(BaseModel):
    dataset: str = "synthetic"
    fault: str | None = None          # all | persistent | None
    approval: bool = True
    memory: bool = True
    model: str | None = None


class ApprovalRequest(BaseModel):
    decisions: dict[str, dict]


class AskRequest(BaseModel):
    question: str


class FeedbackRequest(BaseModel):
    incident_id: str
    verdict: str                      # false_positive | confirmed


class BenchmarkRequest(BaseModel):
    seeds: list[int] = [1, 2, 3, 4, 5]
    sizes: list[int] = [150, 300, 600]
    per_type: int = 6


@app.get("/api/meta")
def meta() -> dict:
    models = ollama_models()
    return {
        "datasets": datasets(),
        "thresholds": {"low": rubric.LOW_THRESHOLD, "high": rubric.HIGH_THRESHOLD,
                       "critical": rubric.CRITICAL_THRESHOLD, "max_retries": rubric.MAX_RETRIES},
        "faults": FAULT_LABELS, "ollama": {"available": bool(models), "models": models}, "nodes": NODE_LABELS,
    }


@app.post("/api/datasets")
def upload_dataset(payload: dict | list = Body(...)) -> dict:
    """Accept {"name": ..., "records": [...]} or a bare list (native alerts or Windows/Sysmon events)."""
    records = payload.get("records") if isinstance(payload, dict) else payload
    name = payload.get("name", "uploaded file") if isinstance(payload, dict) else "uploaded file"
    try:
        alerts, fmt = load_alerts(records, host_ips())
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(400, f"Could not read the file: {exc}") from exc
    if not alerts:
        raise HTTPException(400, "No supported events found in the file.")
    key = uuid.uuid4().hex[:8]
    UPLOADS[key] = {"alerts": alerts, "label": f"{name} ({fmt})"}
    return {"key": f"upload:{key}", "label": UPLOADS[key]["label"], "alerts": len(alerts), "format": fmt}


@app.get("/api/feed")
async def feed(dataset: str = "synthetic", seconds: float = 18) -> StreamingResponse:
    """Replay a dataset as a live alert stream: alerts arrive in time order, candidates form and grow."""
    alerts = sorted(dataset_alerts(dataset)[0], key=lambda a: a["ts"])
    ticks = max(1, min(len(alerts), 70))
    per_tick = -(-len(alerts) // ticks)

    async def stream():
        for start in range(0, len(alerts), per_tick):
            seen = alerts[:start + per_tick]
            cands = []
            for g in group_alerts(seen):
                stages = list(detect_stages(g))
                cands.append({"key": f"{g[0]['host']}@{g[0]['ts'][11:16]}", "host": g[0]["host"], "alerts": len(g),
                              "first": g[0]["ts"], "last": g[-1]["ts"], "stages": stages,
                              "users": sorted({a["user"] for a in g if a["user"]})})
            yield f"data: {json.dumps({'type': 'tick', 'alerts': alerts[start:start + per_tick], 'candidates': cands, 'total': len(alerts)})}\n\n"
            await asyncio.sleep(seconds / ticks)
        yield f"data: {json.dumps({'type': 'end', 'total': len(alerts)})}\n\n"

    return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})


@app.post("/api/runs")
def create_run(req: RunRequest) -> dict:
    alerts, _ = dataset_alerts(req.dataset)
    config = {"data_dir": str(DATA_DIR), **ollama_config(req.model), "fault_mode": req.fault if req.fault in DEMO_MODES else None,
              "require_approval": req.approval, "use_memory": req.memory}
    run = Run(config, alerts, req.dataset)
    RUNS[run.id] = run
    run.start()
    return {"run_id": run.id}


@app.get("/api/runs/{run_id}/events")
async def run_events(run_id: str, since: int = 0) -> StreamingResponse:
    run = get_run(run_id)

    async def stream():
        i = since
        while True:
            while i < len(run.events):
                event = run.events[i]
                i += 1
                yield f"data: {json.dumps({**event, 'seq': i}, default=str)}\n\n"
                if event["type"] in TERMINAL:
                    return
            await asyncio.sleep(0.05)

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/api/runs/{run_id}/approve")
def approve(run_id: str, req: ApprovalRequest) -> dict:
    run = get_run(run_id)
    if run.status != "awaiting_approval":
        raise HTTPException(409, "run is not waiting for approval")
    run.resume(req.decisions)
    return {"ok": True, "since": len(run.events)}


@app.get("/api/runs/{run_id}/result")
def result(run_id: str) -> JSONResponse:
    run = get_run(run_id, done=True)
    state = run.runner.state
    alerts_by_id = {a["id"]: a for a in state["alerts"]}
    stage_of = {}
    for inc in state["incidents"]:
        for stage, ids in detect_stages([alerts_by_id[a] for a in inc["alert_ids"]]).items():
            for aid in ids:
                stage_of[aid] = stage
    final_cp2 = {v["incident_id"]: v for v in state["critic_verdicts"] if v["checkpoint"] == 2}
    observed: dict[str, list[str]] = {}
    for inc in state["incidents"]:
        if inc["route"] != "auto_close":
            for t in inc.get("techniques", []):
                observed.setdefault(t["id"], []).append(inc["id"])
    covered = {t["id"] for inc in state["incidents"] if final_cp2.get(inc["id"], {}).get("passed")
               for t in inc.get("techniques", [])}
    attack = {"tactics": TACTIC_ORDER, "techniques": [{**t, "incidents": observed.get(t["id"], []),
                                                         "covered": t["id"] in covered} for t in catalogue()]}
    payload = {
        "run_id": run.id, "path": run.path, "dataset": run.dataset, "config": run.config,
        "alerts": state["alerts"], "incidents": sorted(state["incidents"], key=lambda i: -i["severity"]),
        "enriched": state["enriched_context"], "verdicts": state["critic_verdicts"],
        "prose_checks": state.get("prose_checks", []), "retries": state["retries"],
        "detection_rule": state["detection_rule"], "playbook": state["playbook"],
        "approvals": state.get("approvals", {}), "tickets": state["ticket"],
        "notifications": state["notifications"], "report": state["report"], "trace": state["trace"],
        "stage_of": stage_of, "attack": attack,
        "evaluation": evaluate(state, load_json("ground_truth.json")) if run.dataset == "synthetic" else None,
    }
    return JSONResponse(json.loads(json.dumps(payload, default=str)))


@app.post("/api/runs/{run_id}/ask")
def ask(run_id: str, req: AskRequest) -> dict:
    run = get_run(run_id, done=True)
    try:
        return answer(req.question, run.runner.state, get_llm(ollama_config(run.config["ollama_model"])))
    except RuntimeError as exc:
        raise HTTPException(502, str(exc)) from exc


@app.post("/api/runs/{run_id}/feedback")
def feedback(run_id: str, req: FeedbackRequest) -> dict:
    """Analyst marks an incident false positive or confirmed; the lesson applies to the next run."""
    state = get_run(run_id, done=True).runner.state
    inc = next((i for i in state["incidents"] if i["id"] == req.incident_id), None)
    if inc is None or req.verdict not in ("false_positive", "confirmed"):
        raise HTTPException(400, "unknown incident or verdict")
    alerts_by_id = {a["id"]: a for a in state["alerts"]}
    learned = memory.learn(inc, [alerts_by_id[a] for a in inc["alert_ids"]], state["enriched_context"],
                           req.verdict, "SOC analyst (web console)")
    return {"ok": True, "learned": learned}


@app.get("/api/memory")
def get_memory() -> dict:
    return memory.load()


@app.delete("/api/memory")
def clear_memory() -> dict:
    memory.clear()
    return {"ok": True}


@app.delete("/api/memory/{kind}/{key}")
def forget_memory(kind: str, key: str) -> dict:
    memory.forget(kind, key)
    return {"ok": True}


@app.post("/api/benchmark")
def start_benchmark(req: BenchmarkRequest) -> dict:
    """Multi-seed benchmark + Critic ablation in the background (deterministic mock model)."""
    from eval.benchmark import run_ablation, run_benchmark

    job_id = uuid.uuid4().hex[:8]
    job = JOBS[job_id] = {"status": "running", "phase": "benchmark", "step": "", "done": 0, "total": 0, "result": None}

    def progress(phase):
        def cb(step, n, total):
            job.update(phase=phase, step=step, done=n, total=total)
        return cb

    def work():
        try:
            bench = run_benchmark(req.seeds, req.sizes, progress("benchmark"))
            abl = run_ablation(req.per_type, progress=progress("ablation"))
            job.update(status="done", result={"benchmark": bench, "ablation": abl,
                                              "finished": datetime.now().strftime("%H:%M:%S")})
        except Exception as exc:
            job.update(status="error", step=f"{type(exc).__name__}: {exc}")

    threading.Thread(target=work, daemon=True).start()
    return {"job_id": job_id}


@app.get("/api/benchmark/{job_id}")
def benchmark_status(job_id: str) -> dict:
    if job_id not in JOBS:
        raise HTTPException(404, "unknown job")
    return JOBS[job_id]


@app.get("/api/runs/{run_id}/export/{kind}")
def export(run_id: str, kind: str, incident: str | None = None) -> Response:
    state = get_run(run_id, done=True).runner.state
    stamp = datetime.now().strftime("%Y%m%d_%H%M")
    if kind == "pdf":
        body, mime, name = (markdown_to_pdf(state["report"]["summary_md"], state["report"]["handover_md"]),
                            "application/pdf", f"soc_report_{stamp}.pdf")
    elif kind == "tickets":
        body, mime, name = tickets_json(state["ticket"]), "application/json", f"tickets_{stamp}.json"
    elif kind == "sigma" and incident in state["detection_rule"]:
        bundle = state["detection_rule"][incident]
        body, mime, name = bundle["sigma"]["sigma"], "text/yaml", f"{bundle['rule']['id'].lower()}.sigma.yml"
    else:
        raise HTTPException(404, "unknown export")
    return Response(body, media_type=mime, headers={"Content-Disposition": f'attachment; filename="{name}"'})


@app.get("/")
def index() -> FileResponse:
    return FileResponse(WEB / "index.html")


@app.on_event("startup")
def load_model() -> None:
    """Warm the default Ollama model in the background so the first run is not slow."""
    models = ollama_models()
    if models:
        threading.Thread(target=warm_up, args=(models[0],), daemon=True).start()


app.mount("/static", StaticFiles(directory=WEB), name="static")
app.mount("/docs-assets", StaticFiles(directory=ROOT / "docs"), name="docs")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=os.environ.get("SOC_HOST", "127.0.0.1"), port=int(os.environ.get("SOC_PORT", "8000")))
