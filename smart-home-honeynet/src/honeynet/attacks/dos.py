"""HTTP request-flood simulator (lab only).

A safer, bounded re-implementation of the raw DoS script from the original
report.  Hard caps on request count and duration, private-target enforcement
and graceful error handling replace the original's unbounded ``while True``
loop.
"""

from __future__ import annotations

import threading
import time
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlparse

from .safety import SafetyError, assert_safe_target

MAX_REQUESTS = 5000       # absolute ceiling regardless of caller input
MAX_DURATION = 60.0       # seconds


@dataclass
class DosResult:
    url: str
    sent: int = 0
    errors: int = 0
    duration: float = 0.0


def dos_flood(
    url: str,
    count: int = 200,
    concurrency: int = 8,
    duration: float = 10.0,
    timeout: float = 2.0,
) -> DosResult:
    """Send up to ``count`` HTTP GET requests across ``concurrency`` threads."""
    host = urlparse(url).hostname or ""
    if not host:
        raise SafetyError(f"Cannot parse host from URL {url!r}")
    assert_safe_target(host)

    count = max(1, min(count, MAX_REQUESTS))
    duration = max(0.1, min(duration, MAX_DURATION))
    concurrency = max(1, min(concurrency, 64))

    result = DosResult(url=url)
    lock = threading.Lock()
    deadline = time.time() + duration
    remaining = {"n": count}
    start = time.time()

    def worker() -> None:
        while True:
            with lock:
                if remaining["n"] <= 0 or time.time() > deadline:
                    return
                remaining["n"] -= 1
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "dos-sim/1.0"})
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    resp.read(64)
                with lock:
                    result.sent += 1
            except Exception:
                with lock:
                    result.errors += 1

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(concurrency)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=MAX_DURATION + 5)
    result.duration = round(time.time() - start, 3)
    return result
