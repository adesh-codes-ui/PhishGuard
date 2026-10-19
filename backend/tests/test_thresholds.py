"""Tests for exploratory threshold analysis utilities."""

from __future__ import annotations

from eval import analyze_thresholds


def test_evaluate_threshold_runs():
    m = analyze_thresholds.evaluate_threshold(25)
    keys = {"tp", "fn", "fp", "tn", "acc", "prec", "rec", "spec", "f1", "fpr"}
    assert keys <= set(m.keys())
    assert sum([m["tp"], m["fn"], m["fp"], m["tn"]]) == 12


def test_multiple_thresholds_consistent():
    m25 = analyze_thresholds.evaluate_threshold(25)
    m50 = analyze_thresholds.evaluate_threshold(50)
    # higher threshold -> more FNs, fewer FPs
    assert m50["fn"] >= m25["fn"]
    assert m50["fp"] <= m25["fp"]
