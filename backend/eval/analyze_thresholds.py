#!/usr/bin/env python3
"""Exploratory threshold analysis for PhishGuard (synthetic fixtures only).

No production thresholds are changed. This is for Day 7 reporting only.
"""

from __future__ import annotations

import sys
from pathlib import Path

if __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from eval import evaluator
from app import analyzer


def metrics(tp, fp, tn, fn):
    total = tp + fp + tn + fn
    acc = (tp + tn) / total if total else 0.0
    prec = tp / (tp + fp) if (tp + fp) else float("nan")
    rec = tp / (tp + fn) if (tp + fn) else float("nan")
    spec = tn / (tn + fp) if (tn + fp) else float("nan")
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec and prec == prec and rec == rec) else float("nan")
    fpr = fp / (fp + tn) if (fp + tn) else float("nan")
    return {
        "acc": acc,
        "prec": prec,
        "rec": rec,
        "spec": spec,
        "f1": f1,
        "fpr": fpr,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
    }


def evaluate_threshold(threshold: int) -> dict:
    """threshold is minimum score to be considered positive (suspicious)."""
    examples = evaluator.load_fixtures()
    tp = fp = tn = fn = 0
    for ex in examples:
        res = analyzer.analyze_url(ex.url)
        pred_pos = res.risk_score >= threshold
        true_pos = ex.label == "suspicious"
        if true_pos and pred_pos:
            tp += 1
        elif true_pos and not pred_pos:
            fn += 1
        elif (not true_pos) and pred_pos:
            fp += 1
        else:
            tn += 1
    return metrics(tp, fp, tn, fn)


def main():
    print("=== Exploratory threshold analysis (synthetic fixtures only) ===")
    print("No production thresholds changed.")
    print("Using score >= T as positive (treating Medium/High/Critical accordingly).")
    print()
    print(f"{'T':>2} {'TP':>2} {'FN':>2} {'FP':>2} {'TN':>2}  {'Acc':>5} {'Prec':>5} {'Rec':>5} {'Spec':>5} {'F1':>5} {'FPR':>5}")
    for t in [0, 10, 15, 20, 25, 30, 40, 50, 65, 75]:
        m = evaluate_threshold(t)
        print(
            f"{t:2d} {m['tp']:2d} {m['fn']:2d} {m['fp']:2d} {m['tn']:2d}  {m['acc']:.3f} {m['prec']:.3f} {m['rec']:.3f} {m['spec']:.3f} {m['f1']:.3f} {m['fpr']:.3f}"
        )
    print()
    print("Current production bands: Low 0-24, Medium 25-49, High 50-74, Critical 75-100")
    print("Current evaluator uses High/Critical as positive (T effectively ~50).")
    print("Recommendation: Do NOT choose T from this set; use a separate held-out dataset.")


if __name__ == "__main__":
    main()
