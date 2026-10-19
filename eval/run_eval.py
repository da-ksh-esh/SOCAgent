"""Evaluate a run against ground truth (never read by the agents).

Chain metrics: an attack chain is correctly correlated when all its alerts land in one incident
with the expected severity band. Alert metrics: an alert counts as flagged when it sits in an
incident that was queued or escalated (severity >= 40); attack alerts are positives.

Usage: python eval/run_eval.py            (demo dataset, then the full benchmark)
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.paths import DATA_DIR, load_json  # noqa: E402


def alert_metrics(incidents: list[dict], truth: dict) -> dict:
    attack = {a for c in truth["chains"].values() for a in c["alert_ids"]}
    flagged = {a for i in incidents if i["band"] != "low" for a in i["alert_ids"]}
    tp, fp, fn = len(attack & flagged), len(flagged - attack), len(attack - flagged)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": round(precision, 3), "recall": round(recall, 3),
            "f1": round(f1, 3)}


def evaluate(state: dict, ground_truth: dict) -> dict:
    incidents = state["incidents"]
    chains = []
    for key, chain in ground_truth["chains"].items():
        ids = set(chain["alert_ids"])
        best = max(incidents, key=lambda i: len(ids & set(i["alert_ids"])))
        covered = ids <= set(best["alert_ids"])
        chains.append({
            "chain": key, "name": chain["name"], "incident": best["id"], "severity": best["severity"],
            "expected_band": chain["expected_band"], "actual_band": best["band"],
            "alerts_found": f"{len(ids & set(best['alert_ids']))}/{len(ids)}",
            "extra_alerts": len(set(best["alert_ids"]) - ids), "hosts": best.get("hosts", [best["host"]]),
            "correct": covered and best["band"] == chain["expected_band"],
        })
    benign = set(ground_truth["benign_alert_ids"])
    escalated_benign = sorted({a for i in incidents if i["band"] != "low" for a in i["alert_ids"] if a in benign})
    finals = {v["incident_id"]: v for v in state["critic_verdicts"] if v["checkpoint"] == 2}  # last attempt wins
    return {
        "attacks_correlated": sum(c["correct"] for c in chains), "attacks_total": len(chains),
        "benign_wrongly_escalated": len(escalated_benign), "benign_total": len(benign),
        "escalated_benign_ids": escalated_benign,
        "critic_retries": state["retries"]["cp1"] + state["retries"]["cp2"],
        "critic_rejections": sum(1 for v in state["critic_verdicts"] if not v["passed"]),
        "prose_rewrites": sum(len(p["rejections"]) for p in state.get("prose_checks", [])),
        "rule_tests_passed": sum(v["rule_tests"]["passed"] for v in finals.values()), "rule_tests_total": len(finals),
        "auto_closed": sum(1 for i in incidents if i["route"] == "auto_close"),
        "incidents": len(incidents), "chains": chains, "alerts": alert_metrics(incidents, ground_truth),
    }


def main() -> None:
    from eval.benchmark import print_report, run_ablation, run_benchmark
    from graph import run

    truth = load_json("ground_truth.json")
    r = evaluate(run(load_json("alerts.json"), {"data_dir": str(DATA_DIR), "mode": "mock"}), truth)
    print(f"== demo dataset (seed {truth.get('seed', '?')}) ==")
    print(f"Attacks correctly correlated : {r['attacks_correlated']}/{r['attacks_total']}")
    for c in r["chains"]:
        print(f"   {c['chain']}: {c['incident']} score {c['severity']} band {c['actual_band']} "
              f"(expected {c['expected_band']}), alerts {c['alerts_found']}, hosts {', '.join(c['hosts'])}"
              f" -> {'OK' if c['correct'] else 'MISS'}")
    print(f"Benign alerts wrongly escalated: {r['benign_wrongly_escalated']}/{r['benign_total']}")
    print(f"Alert precision/recall/F1    : {r['alerts']['precision']} / {r['alerts']['recall']} / {r['alerts']['f1']}")
    print(f"Rule tests passed            : {r['rule_tests_passed']}/{r['rule_tests_total']}")
    print_report(run_benchmark(), run_ablation())


if __name__ == "__main__":
    main()
