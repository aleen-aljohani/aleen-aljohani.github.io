"""Hybrid detection engine.

Combines two of the approaches described in the original report:

* **Signature-based** — known-bad indicators such as Mirai default
  credentials, IoT exploitation URLs and shell-injection payloads.
* **Anomaly / threshold-based** — sliding-window counters that flag
  brute-force, denial-of-service and port-scan behaviour by rate.

The engine is stream-oriented: ``process(event)`` is called once per
honeypot observation and returns any *new* alerts.  A per-(source, rule)
cooldown prevents a single sustained attack from producing thousands of
duplicate alerts.
"""

from __future__ import annotations

import re
import threading
from collections import defaultdict, deque
from datetime import datetime
from typing import Deque, Optional

from ..config import DetectionConfig
from ..mitre import lookup
from ..models import Alert, Event, EventType, Severity


def _epoch(ts: str) -> float:
    try:
        return datetime.fromisoformat(ts).timestamp()
    except ValueError:
        return datetime.now().timestamp()


class DetectionEngine:
    def __init__(self, config: Optional[DetectionConfig] = None) -> None:
        self.config = config or DetectionConfig()
        self._lock = threading.Lock()

        # sliding-window state keyed by source ip
        self._failed_logins: dict[str, Deque[float]] = defaultdict(deque)
        self._requests: dict[str, Deque[float]] = defaultdict(deque)
        self._ports: dict[str, Deque[tuple[float, int]]] = defaultdict(deque)

        # cooldown bookkeeping: (source_ip, rule_id) -> last alert epoch
        self._last_alert: dict[tuple[str, str], float] = {}

        self._mirai = {(u.lower(), p) for u, p in self.config.mirai_credentials}
        self._suspicious = [re.compile(p, re.I) for p in self.config.suspicious_http_patterns]
        self._injection = [re.compile(p, re.I) for p in self.config.injection_patterns]

    # ------------------------------------------------------------------
    def process(self, event: Event) -> list[Alert]:
        """Feed one event through every rule; return newly raised alerts."""
        with self._lock:
            alerts: list[Alert] = []
            ts = _epoch(event.timestamp)

            self._check_default_credentials(event, alerts)
            self._check_brute_force(event, ts, alerts)
            self._check_dos(event, ts, alerts)
            self._check_port_scan(event, ts, alerts)
            self._check_signatures(event, alerts)
            return alerts

    # -- rules ----------------------------------------------------------
    def _emit(self, event: Event, ts_now: float, alerts: list[Alert], *,
              rule_id: str, category: str, severity: str, description: str,
              event_count: int = 1) -> None:
        key = (event.source_ip, rule_id)
        last = self._last_alert.get(key)
        if last is not None and (ts_now - last) < self.config.alert_cooldown:
            return
        self._last_alert[key] = ts_now
        tech = lookup(category)
        alerts.append(Alert(
            rule_id=rule_id,
            category=category,
            severity=severity,
            source_ip=event.source_ip,
            description=description,
            honeypot=event.honeypot,
            event_count=event_count,
            mitre_technique=tech.technique_id,
            mitre_name=tech.name,
            first_seen=event.timestamp,
            last_seen=event.timestamp,
            raw={"tactic": tech.tactic, "trigger_event": event.event_id},
        ))

    def _check_default_credentials(self, event: Event, alerts: list[Alert]) -> None:
        if event.event_type != EventType.LOGIN_ATTEMPT:
            return
        if event.username is None or event.password is None:
            return
        if (event.username.lower(), event.password) in self._mirai:
            self._emit(
                event, _epoch(event.timestamp), alerts,
                rule_id="IOT-DEFAULT-CREDS",
                category="default-credentials",
                severity=Severity.HIGH,
                description=(
                    f"Known IoT/Mirai default credential used: "
                    f"{event.username}:{event.password}"
                ),
            )

    def _check_brute_force(self, event: Event, ts: float, alerts: list[Alert]) -> None:
        if event.event_type != EventType.LOGIN_ATTEMPT or event.success:
            return
        window = self._failed_logins[event.source_ip]
        window.append(ts)
        self._trim(window, ts, self.config.brute_force_window)
        if len(window) >= self.config.brute_force_threshold:
            self._emit(
                event, ts, alerts,
                rule_id="SSH-TELNET-BRUTE-FORCE",
                category="brute-force",
                severity=Severity.HIGH,
                description=(
                    f"{len(window)} failed logins from {event.source_ip} "
                    f"within {self.config.brute_force_window}s"
                ),
                event_count=len(window),
            )

    def _check_dos(self, event: Event, ts: float, alerts: list[Alert]) -> None:
        if event.event_type not in (EventType.HTTP_REQUEST, EventType.CONNECTION):
            return
        window = self._requests[event.source_ip]
        window.append(ts)
        self._trim(window, ts, self.config.dos_window)
        if len(window) >= self.config.dos_threshold:
            self._emit(
                event, ts, alerts,
                rule_id="HTTP-DOS-FLOOD",
                category="denial-of-service",
                severity=Severity.CRITICAL,
                description=(
                    f"Possible DoS flood: {len(window)} requests from "
                    f"{event.source_ip} within {self.config.dos_window}s"
                ),
                event_count=len(window),
            )

    def _check_port_scan(self, event: Event, ts: float, alerts: list[Alert]) -> None:
        if event.dest_port is None:
            return
        window = self._ports[event.source_ip]
        window.append((ts, event.dest_port))
        while window and ts - window[0][0] > self.config.port_scan_window:
            window.popleft()
        distinct = {p for _, p in window}
        if len(distinct) >= self.config.port_scan_threshold:
            self._emit(
                event, ts, alerts,
                rule_id="PORT-SCAN",
                category="reconnaissance",
                severity=Severity.MEDIUM,
                description=(
                    f"Port scan: {len(distinct)} distinct ports probed by "
                    f"{event.source_ip} within {self.config.port_scan_window}s"
                ),
                event_count=len(distinct),
            )

    def _check_signatures(self, event: Event, alerts: list[Alert]) -> None:
        ts = _epoch(event.timestamp)
        haystacks = [h for h in (event.http_path, event.command) if h]
        for hay in haystacks:
            for rx in self._injection:
                if rx.search(hay):
                    self._emit(
                        event, ts, alerts,
                        rule_id="CMD-INJECTION",
                        category="command-injection",
                        severity=Severity.CRITICAL,
                        description=f"Command-injection payload detected: {hay[:120]}",
                    )
                    break
        if event.http_path:
            for rx in self._suspicious:
                if rx.search(event.http_path):
                    self._emit(
                        event, ts, alerts,
                        rule_id="SUSPICIOUS-HTTP-PATH",
                        category="active-scanning",
                        severity=Severity.MEDIUM,
                        description=f"Suspicious IoT exploitation path: {event.http_path[:120]}",
                    )
                    break

    @staticmethod
    def _trim(window: Deque[float], now: float, span: int) -> None:
        while window and now - window[0] > span:
            window.popleft()

    # ------------------------------------------------------------------
    def replay(self, events: list[Event]) -> list[Alert]:
        """Run a batch of events through the engine (used for analysis/tests)."""
        out: list[Alert] = []
        for ev in events:
            out.extend(self.process(ev))
        return out
