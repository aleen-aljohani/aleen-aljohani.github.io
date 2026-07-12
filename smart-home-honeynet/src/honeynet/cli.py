"""Command-line interface for SmartHoneyNet.

Sub-commands
------------
serve     Start the honeypots and detection pipeline (runs until Ctrl-C).
demo      Run a fully self-contained end-to-end demonstration.
analyze   Read an existing database and emit a threat-analysis report.
attack    Run a lab attack simulation against a running honeynet.
"""

from __future__ import annotations

import argparse
import signal
import sys
import time
from pathlib import Path

from .analysis import Analyzer, render_json, render_markdown
from .config import Settings
from .database import Database
from .service import HoneyNet


def _cmd_serve(args: argparse.Namespace) -> int:
    settings = Settings.from_env(
        telnet_port=args.telnet_port,
        http_port=args.http_port,
        database_path=args.db,
    )
    net = HoneyNet.build(settings).start()
    print(f"[+] Telnet honeypot  : {settings.telnet_host}:{net.telnet.port}")
    print(f"[+] HTTP honeypot    : {settings.http_host}:{net.http.port}")
    print(f"[+] Database         : {settings.database_path}")
    print("[+] Press Ctrl-C to stop.")

    stop = {"flag": False}

    def _handle(signum, frame):  # noqa: ANN001
        stop["flag"] = True

    signal.signal(signal.SIGINT, _handle)
    signal.signal(signal.SIGTERM, _handle)
    try:
        while not stop["flag"]:
            time.sleep(0.3)
    finally:
        net.stop()
    print("\n[+] Stopped.")
    return 0


def _cmd_demo(args: argparse.Namespace) -> int:
    from .demo import run_demo

    return run_demo(db_path=args.db, out=args.out)


def _cmd_analyze(args: argparse.Namespace) -> int:
    if not Path(args.db).exists():
        print(f"error: database {args.db!r} not found", file=sys.stderr)
        return 2
    db = Database(args.db)
    try:
        summary = Analyzer(db).summarize(top_n=args.top)
    finally:
        db.close()
    text = render_json(summary) if args.format == "json" else render_markdown(summary)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"[+] Report written to {args.out}")
    else:
        print(text)
    return 0


def _cmd_attack(args: argparse.Namespace) -> int:
    from .attacks import brute_force, dos_flood, port_scan

    if args.kind == "brute-force":
        res = brute_force(args.host, args.port)
        print(f"attempts={res.attempts} accepted={res.succeeded}")
    elif args.kind == "dos":
        res = dos_flood(args.url, count=args.count, concurrency=args.concurrency)
        print(f"sent={res.sent} errors={res.errors} duration={res.duration}s")
    elif args.kind == "port-scan":
        res = port_scan(args.host)
        print(f"open={res.open_ports} closed={res.closed_ports}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="honeynet", description="SmartHoneyNet control tool")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("serve", help="run honeypots + detection pipeline")
    sp.add_argument("--telnet-port", type=int, default=2323)
    sp.add_argument("--http-port", type=int, default=8080)
    sp.add_argument("--db", default="honeynet.db")
    sp.set_defaults(func=_cmd_serve)

    dp = sub.add_parser("demo", help="run a self-contained end-to-end demo")
    dp.add_argument("--db", default="demo.db")
    dp.add_argument("--out", default="reports/demo-report.md")
    dp.set_defaults(func=_cmd_demo)

    ap = sub.add_parser("analyze", help="generate a threat-analysis report")
    ap.add_argument("--db", default="honeynet.db")
    ap.add_argument("--format", choices=["markdown", "json"], default="markdown")
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--out", default=None)
    ap.set_defaults(func=_cmd_analyze)

    kp = sub.add_parser("attack", help="run a lab attack simulation")
    ksub = kp.add_subparsers(dest="kind", required=True)
    bf = ksub.add_parser("brute-force")
    bf.add_argument("--host", default="127.0.0.1")
    bf.add_argument("--port", type=int, default=2323)
    ds = ksub.add_parser("dos")
    ds.add_argument("--url", default="http://127.0.0.1:8080/")
    ds.add_argument("--count", type=int, default=200)
    ds.add_argument("--concurrency", type=int, default=8)
    ps = ksub.add_parser("port-scan")
    ps.add_argument("--host", default="127.0.0.1")
    kp.set_defaults(func=_cmd_attack)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
