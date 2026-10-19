"""Benchmark: detection quality across many datasets, and a Critic ablation over injected faults.

run_benchmark  seeds x noise levels -> precision / recall / F1 on attack alerts, chains detected,
               benign incidents escalated (mock LLM, no memory, no approval pause: deterministic).
run_ablation   N random faults (type, target, dataset) run twice: Critic enforcing vs Critic disabled.
               A fault is "caught" when the Critic rejects work, "corrected" when the final output no
               longer contains the defect, and "shipped" when the defect reaches the final output.
"""
from __future__ import annotations

import random
import statistics
import sys
import time
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.critic import fact_check, missing_lookups, recompute_from_evidence  # noqa: E402
from core.faults import FAULT_AGENT, FAULT_TYPES, HALLUCINATED_IP  # noqa: E402
from core.paths import DATA_DIR, load_json  # noqa: E402
from eval.run_eval import evaluate  # noqa: E402
from graph import run  # noqa: E402
from scripts.generate_data import generate_dataset  # noqa: E402
from tools.playbooks import check_playbook_order  # noqa: E402
from tools.rules import run_rule_tests  # noqa: E402

SEEDS = [1, 2, 3, 4, 5]
SIZES = [150, 300, 600]
Progress = Callable[[str, int, int], None] | None


def base_config(**extra) -> dict:
    return {"data_dir": str(DATA_DIR), "mode": "mock", **extra}


def integrity_defects(state: dict) -> set[str]:
    """Defects present in a run's final output, named after the fault that would cause them."""
    alerts_by_id = {a["id"]: a for a in state["alerts"]}
    enriched = state["enriched_context"]
    defects = set()
    for inc in state["incidents"]:
        if any(not c["alert_ids"] for c in inc["claims"]):
            defects.add("drop_evidence")
        parts, problems = recompute_from_evidence(inc, alerts_by_id, enriched)
        if any("not supported" in p for p in problems):
            defects.add("fake_stage")
        if parts["total"] != inc["severity"]:
            defects.add("inflate_score")
        if missing_lookups(inc, alerts_by_id, enriched):
            defects.add("skip_lookup")
        if HALLUCINATED_IP in inc.get("summary", "") or fact_check(inc.get("summary", ""), str(state["alerts"]) + str(inc)):
            defects.add("hallucinate")
    benign = load_json("benign_logs.json")
    for iid, bundle in state["detection_rule"].items():
        own = [alerts_by_id[a] for a in next(i for i in state["incidents"] if i["id"] == iid)["alert_ids"]]
        if not run_rule_tests(bundle["rule"], own, benign, own)["silent_on_benign"]:
            defects.add("broad_rule")
    if any(check_playbook_order(p) for p in state["playbook"].values()):
        defects.add("unsafe_playbook")
    return defects


def run_benchmark(seeds: list[int] = SEEDS, sizes: list[int] = SIZES, progress: Progress = None) -> dict:
    rows, total, n = [], len(seeds) * len(sizes), 0
    for size in sizes:
        for seed in seeds:
            n += 1
            if progress:
                progress(f"dataset seed {seed}, {size} alerts", n, total)
            alerts, truth = generate_dataset(seed, size)
            t0 = time.perf_counter()
            state = run(alerts, base_config())
            r = evaluate(state, truth)
            rows.append({"seed": seed, "alerts": len(alerts), "size": size, **r["alerts"],
                         "chains": f"{r['attacks_correlated']}/{r['attacks_total']}",
                         "chains_ok": r["attacks_correlated"], "chains_total": r["attacks_total"],
                         "benign_incidents_escalated": sum(1 for i in state["incidents"] if i["band"] != "low"
                                                           and set(i["alert_ids"]) <= set(truth["benign_alert_ids"])),
                         "seconds": round(time.perf_counter() - t0, 2)})
    summary = []
    for size in sizes:
        rs = [r for r in rows if r["size"] == size]
        stat = lambda k: (round(statistics.mean(r[k] for r in rs), 3), round(statistics.pstdev(r[k] for r in rs), 3))
        summary.append({"size": size, "runs": len(rs), "precision": stat("precision"), "recall": stat("recall"),
                        "f1": stat("f1"), "chains_detected": f"{sum(r['chains_ok'] for r in rs)}/{sum(r['chains_total'] for r in rs)}",
                        "benign_incidents_escalated": sum(r["benign_incidents_escalated"] for r in rs)})
    return {"rows": rows, "summary": summary}


def run_ablation(per_type: int = 6, seed: int = 7, progress: Progress = None) -> dict:
    rng = random.Random(seed)
    trials = [(ftype, rng.randint(0, 2), rng.randint(100, 999)) for ftype in FAULT_TYPES for _ in range(per_type)]
    results = []
    for n, (ftype, pick, data_seed) in enumerate(trials, start=1):
        if progress:
            progress(f"fault {ftype} (target #{pick}, dataset {data_seed})", n, len(trials))
        alerts, _ = generate_dataset(data_seed, 150)
        fault = [{"type": ftype, "pick": pick, "persistent": False}]
        on = run(alerts, base_config(faults=fault))
        off = run(alerts, base_config(faults=fault, critic_enabled=False))
        caught = any(not v["passed"] for v in on["critic_verdicts"]) or any(p["rejections"] for p in on["prose_checks"])
        results.append({"type": ftype, "agent": FAULT_AGENT[ftype], "pick": pick, "dataset": data_seed,
                        "caught": caught, "corrected": ftype not in integrity_defects(on),
                        "shipped_without_critic": ftype in integrity_defects(off)})
    table = []
    for ftype in FAULT_TYPES:
        rs = [r for r in results if r["type"] == ftype]
        table.append({"fault": ftype, "agent": FAULT_AGENT[ftype], "injected": len(rs),
                      "caught": sum(r["caught"] for r in rs), "corrected": sum(r["corrected"] for r in rs),
                      "shipped_without_critic": sum(r["shipped_without_critic"] for r in rs)})
    tot = {k: sum(r[k] for r in table) for k in ("injected", "caught", "corrected", "shipped_without_critic")}
    return {"trials": results, "table": table, "total": tot}


def print_report(bench: dict, ablation: dict) -> None:
    print("\n== benchmark: attack-alert detection across datasets (mean ± std) ==")
    print(f"{'alerts':>7} {'runs':>4} {'precision':>14} {'recall':>14} {'F1':>14} {'chains':>8} {'benign esc.':>11}")
    for s in bench["summary"]:
        fmt = lambda v: f"{v[0]:.3f} ± {v[1]:.3f}"
        print(f"{s['size']:>7} {s['runs']:>4} {fmt(s['precision']):>14} {fmt(s['recall']):>14} {fmt(s['f1']):>14} "
              f"{s['chains_detected']:>8} {s['benign_incidents_escalated']:>11}")
    print("\n== ablation: injected faults, Critic on vs off ==")
    print(f"{'fault':<16} {'agent':<21} {'injected':>8} {'caught':>7} {'corrected':>9} {'shipped w/o Critic':>19}")
    for r in ablation["table"]:
        print(f"{r['fault']:<16} {r['agent']:<21} {r['injected']:>8} {r['caught']:>7} {r['corrected']:>9} {r['shipped_without_critic']:>19}")
    t = ablation["total"]
    print(f"{'TOTAL':<38} {t['injected']:>8} {t['caught']:>7} {t['corrected']:>9} {t['shipped_without_critic']:>19}")


if __name__ == "__main__":
    print_report(run_benchmark(), run_ablation())
