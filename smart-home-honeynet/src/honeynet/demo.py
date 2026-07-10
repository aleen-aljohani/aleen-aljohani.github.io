"""Self-contained end-to-end demonstration.

Spins up both honeypots on ephemeral ports, launches the lab attack
simulators against them, lets the detection engine classify the traffic,
then renders a threat-analysis report — all in a single process, no VMs and
no external services required.  This is the reproducible equivalent of the
three-VM lab described in the original report.
"""

from __future__ import annotations

import time
from pathlib import Path

from .analysis import Analyzer, render_markdown
from .attacks import brute_force, dos_flood, port_scan
from .config import Settings
from .service import HoneyNet


def run_demo(db_path: str = "demo.db", out: str | None = "reports/demo-report.md") -> int:
    # fresh database each run
    if db_path != ":memory:" and Path(db_path).exists():
        Path(db_path).unlink()

    settings = Settings.from_env(
        telnet_host="127.0.0.1", telnet_port=0,
        http_host="127.0.0.1", http_port=0,
        database_path=db_path,
        events_jsonl="logs/demo-events.jsonl",
        alerts_jsonl="logs/demo-alerts.jsonl",
    )

    raised: list = []
    net = HoneyNet.build(settings, on_alert=raised.append).start()
    telnet_port = net.telnet.port
    http_port = net.http.port
    http_url = f"http://127.0.0.1:{http_port}/"

    print("=" * 68)
    print("SmartHoneyNet — end-to-end demonstration")
    print("=" * 68)
    print(f"[+] Telnet honeypot on 127.0.0.1:{telnet_port}")
    print(f"[+] HTTP   honeypot on 127.0.0.1:{http_port}\n")

    try:
        # 1) reconnaissance
        print("[*] Phase 1: port scan (reconnaissance)")
        scan = port_scan("127.0.0.1", ports=[telnet_port, http_port, 21, 22, 25,
                                             111, 139, 445, 3306, 5900])
        print(f"    open ports discovered: {scan.open_ports}")

        # 2) credential brute force against telnet — a wordlist of mostly
        #    wrong guesses (exercises the rate-based rule) plus the IoT
        #    defaults (exercises the signature rule).
        print("[*] Phase 2: telnet brute-force with IoT default credentials")
        from .attacks.brute_force import DEFAULT_WORDLIST
        wrong = [("root", f"guess{i}") for i in range(8)]
        bf = brute_force("127.0.0.1", telnet_port, wordlist=wrong + DEFAULT_WORDLIST)
        print(f"    attempts={bf.attempts} accepted={bf.succeeded}")

        # 3) HTTP request flood (DoS)
        print("[*] Phase 3: HTTP request flood (DoS)")
        flood = dos_flood(http_url, count=120, concurrency=10, duration=8.0)
        print(f"    requests sent={flood.sent} errors={flood.errors}")

        # 4) web scanning / exploitation probes
        print("[*] Phase 4: IoT web-exploitation probes")
        _probe_exploits(http_url)

        # allow async handlers to drain
        time.sleep(0.5)
    finally:
        summary = Analyzer(net.db).summarize()
        net.stop()

    print("\n[+] Detection results")
    print(f"    events captured : {summary.total_events}")
    print(f"    alerts raised   : {summary.total_alerts}")
    for cat, count in summary.alert_categories:
        print(f"      - {cat:22} {count}")

    report = render_markdown(summary)
    if out:
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text(report, encoding="utf-8")
        print(f"\n[+] Full Markdown report written to {out}")
    return 0


def _probe_exploits(base_url: str) -> None:
    import urllib.request

    paths = [
        "/cgi-bin/mainfunction.cgi?action=login&cmd=;wget",
        "/boaform/admin/formLogin",
        "/HNAP1",
        "/../../etc/passwd",
        "/setup.cgi?next_file=netgear.cfg",
    ]
    for p in paths:
        try:
            req = urllib.request.Request(base_url.rstrip("/") + p,
                                         headers={"User-Agent": "Hello, World"})
            urllib.request.urlopen(req, timeout=2).read(16)
        except Exception:
            pass


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(run_demo())
