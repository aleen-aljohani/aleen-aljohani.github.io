"""Regression guard on the labelled evaluation set (see scripts/evaluate.py)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import evaluate  # noqa: E402


def test_evaluation_perfect_on_controlled_set():
    r = evaluate.evaluate()
    assert r["micro_recall"] == 1.0
    assert r["micro_precision"] == 1.0
    assert r["benign_false_positive_sources"] == 0
    for cat, m in r["per_category"].items():
        assert m["recall"] == 1.0, f"{cat} recall regressed"
        assert m["precision"] == 1.0, f"{cat} precision regressed"
