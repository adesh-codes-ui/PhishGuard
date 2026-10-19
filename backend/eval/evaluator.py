#!/usr/bin/env python3
"""Simple offline evaluator for PhishGuard heuristics.

Runs against fixtures.jsonl (synthetic, offline). No network I/O.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

if __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.analyzer import analyze_url, InvalidURLError  # noqa

EVAL_DIR = Path(__file__).resolve().parent
FIXTURES = EVAL_DIR / "fixtures.jsonl"

HIGH_RISK_LABELS = {"High", "Critical"}
LEGIT_LABELS = {"Low", "Medium"}


@dataclass
class Example:
    url: str
    label: str  # 'legit' or 'suspicious'


def load_fixtures(path: Path = FIXTURES) -> List[Example]:
    items: List[Example] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            obj = json.loads(line)
            items.append(Example(url=obj["url"], label=obj["label"]))
    return items


def predict_high_risk(url: str) -> Tuple[bool, str]:
    try:
        res = analyze_url(url)
        pred = res.risk_label in HIGH_RISK_LABELS
        return pred, res.risk_label
    except InvalidURLError as e:
        return False, f"ERROR({e})"


def evaluate(examples: Iterable[Example]) -> Tuple[dict, List[tuple]]:
    examples_list = list(examples)
    tp = tn = fp = fn = 0
    errors = 0

    rows: List[tuple] = []
    for ex in examples_list:
        pred_high, info = predict_high_risk(ex.url)
        true_high = ex.label == "suspicious"
        if ex.label == "legit":
            if pred_high:
                fp += 1
                rows.append((ex.url, ex.label, info, "FP"))
            else:
                tn += 1
                rows.append((ex.url, ex.label, info, "TN"))
        else:  # suspicious
            if pred_high:
                tp += 1
                rows.append((ex.url, ex.label, "HIGH(" + info + ")", "TP"))
            else:
                fn += 1
                rows.append((ex.url, ex.label, info, "FN"))
                if "ERROR" in info:
                    errors += 1

    total = len(examples_list)
    metrics = {
        "total": total,
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
        "errors": errors,
        "accuracy": (tp + tn) / total if total else 0.0,
        "precision": (tp / (tp + fp)) if (tp + fp) else float("nan"),
        "recall": (tp / (tp + fn)) if (tp + fn) else float("nan"),
        "specificity": (tn / (tn + fp)) if (tn + fp) else float("nan"),
    }
    # F1
    p = metrics["precision"]
    r = metrics["recall"]
    metrics["f1"] = (2 * p * r / (p + r)) if (p + r and not (p != p or r != r)) and not (isinstance(p, float) and p != p) and not (isinstance(r, float) and r != r) else float("nan")
    return metrics, rows


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        description="Offline heuristic evaluation for PhishGuard (no network I/O)."
    )
    parser.add_argument(
        "--fixtures",
        type=Path,
        default=FIXTURES,
        help="JSONL dataset with url/label rows (default: synthetic fixtures.jsonl)",
    )
    args = parser.parse_args(argv)

    examples = load_fixtures(args.fixtures)
    metrics, rows = evaluate(examples)
    is_default_dataset = args.fixtures == FIXTURES
    dataset_desc = "synthetic fixtures" if is_default_dataset else str(args.fixtures)

    print(f"=== Offline heuristic evaluation ({dataset_desc}, no network) ===")
    print(f"Fixtures: {metrics['total']} | TP={metrics['tp']} FN={metrics['fn']} FP={metrics['fp']} TN={metrics['tn']} | errors={metrics['errors']}")
    print()
    print("Confusion (threshold: High/Critical = positive = suspicious):")
    print("                ACTUAL_SUSP    ACTUAL_LEGIT")
    print(f"PRED_HIGH                {metrics['tp']:3d}           {metrics['fp']:3d}")
    print(f"PRED_LOW/MED             {metrics['fn']:3d}           {metrics['tn']:3d}")
    print()
    print("Metrics:")
    print(f"Accuracy:  {metrics['accuracy']:.3f}")
    print(f"Precision: {metrics['precision']:.3f}")
    print(f"Recall:    {metrics['recall']:.3f}")
    print(f"Specificity: {metrics['specificity']:.3f}")
    print(f"F1:        {metrics['f1']:.3f}")
    print()
    print("=== Per-example breakdown ===")
    for ex_url, ex_label, info, typ in rows:
        print(f"{typ:3s} {ex_label:10s} -> {info:20s} | {ex_url}")
    print()
    if is_default_dataset:
        print("LIMITATIONS: Small synthetic set; do NOT claim real-world performance.")
        print("Use a separate held-out dataset for later evaluation (no weights tuned on this set).")
    else:
        print(f"LIMITATIONS: external dataset ({dataset_desc}).")
        print("Labels come from the source; see the .meta.json provenance sidecar.")
        print("No URL in this file was fetched, resolved or submitted by the tooling.")
        print("Do NOT tune heuristic weights or production thresholds on held-out data.")


if __name__ == "__main__":
    main()
