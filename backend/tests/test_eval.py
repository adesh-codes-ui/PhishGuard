"""Tests for the evaluation utilities."""

from __future__ import annotations

from eval import evaluator


def test_load_fixtures_non_empty():
    examples = evaluator.load_fixtures()
    assert len(examples) > 0
    assert all(ex.label in ("legit", "suspicious") for ex in examples)
    assert all(ex.url.strip() for ex in examples)


def test_predict_high_risk_behaves():
    pred, info = evaluator.predict_high_risk("https://www.example.com/")
    assert info
    pred2, info2 = evaluator.predict_high_risk("http://192.168.0.1/")
    assert info2
    assert pred is not None and pred2 is not None


def test_evaluate_runs():
    examples = evaluator.load_fixtures()
    metrics, rows = evaluator.evaluate(examples)
    assert metrics["total"] == len(examples)
    assert len(rows) == metrics["total"]
    assert "accuracy" in metrics
    assert "precision" in metrics
    assert "recall" in metrics
    assert "specificity" in metrics
    assert "f1" in metrics
