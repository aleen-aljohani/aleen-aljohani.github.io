"""End-to-end integration test exercising the whole stack in-process."""

import time

from honeynet.analysis import Analyzer
from honeynet.attacks import brute_force, dos_flood
from honeynet.attacks.brute_force import DEFAULT_WORDLIST
from honeynet.config import Settings
from honeynet.service import HoneyNet


def test_full_stack_detects_multiple_attack_types():
    settings = Settings.from_env(
        telnet_host="127.0.0.1", telnet_port=0,
        http_host="127.0.0.1", http_port=0,
        database_path=":memory:",
        events_jsonl=None, alerts_jsonl=None,
    )
    raised = []
    net = HoneyNet.build(settings, on_alert=raised.append).start()
    try:
        wrong = [("root", f"g{i}") for i in range(8)]
        brute_force("127.0.0.1", net.telnet.port, wordlist=wrong + DEFAULT_WORDLIST)
        dos_flood(f"http://127.0.0.1:{net.http.port}/", count=120,
                  concurrency=10, duration=8.0)
        time.sleep(0.3)
        summary = Analyzer(net.db).summarize()
    finally:
        net.stop()

    categories = {c for c, _ in summary.alert_categories}
    assert "default-credentials" in categories
    assert "brute-force" in categories
    assert "denial-of-service" in categories
    assert summary.total_events > 50


def test_demo_runs_and_writes_report(tmp_path):
    from honeynet.demo import run_demo

    out = tmp_path / "report.md"
    rc = run_demo(db_path=str(tmp_path / "demo.db"), out=str(out))
    assert rc == 0
    assert out.exists()
    assert "Threat Analysis Report" in out.read_text()
