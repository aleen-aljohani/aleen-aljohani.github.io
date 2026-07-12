"""Event pipeline: honeypot sensor -> database + IDS + ELK feed.

This is the software equivalent of Logstash in the original architecture.
Every honeypot event flows through :meth:`Pipeline.handle`, which:

1. persists the raw event to SQLite (the local system of record);
2. mirrors it as a JSON line for Filebeat/Logstash -> Elasticsearch;
3. runs it through the detection engine and persists any alerts;
4. notifies optional callbacks (e.g. console alerting).
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Callable, Optional

from .database import Database
from .detection.engine import DetectionEngine
from .models import Alert, Event

AlertCallback = Callable[[Alert], None]


class Pipeline:
    def __init__(
        self,
        db: Database,
        engine: DetectionEngine,
        events_jsonl: Optional[str] = None,
        alerts_jsonl: Optional[str] = None,
        on_alert: Optional[AlertCallback] = None,
    ) -> None:
        self.db = db
        self.engine = engine
        self.events_jsonl = events_jsonl
        self.alerts_jsonl = alerts_jsonl
        self.on_alert = on_alert
        self._file_lock = threading.Lock()
        for p in (events_jsonl, alerts_jsonl):
            if p:
                Path(p).parent.mkdir(parents=True, exist_ok=True)

    def handle(self, event: Event) -> list[Alert]:
        """Thread-safe entry point invoked by every honeypot sensor."""
        self.db.insert_event(event)
        self._append(self.events_jsonl, event.to_json())

        alerts = self.engine.process(event)
        for alert in alerts:
            self.db.insert_alert(alert)
            self._append(self.alerts_jsonl, alert.to_json())
            if self.on_alert:
                try:
                    self.on_alert(alert)
                except Exception:  # pragma: no cover - alert sink must never break ingest
                    pass
        return alerts

    def _append(self, path: Optional[str], line: str) -> None:
        if not path:
            return
        with self._file_lock:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    # convenient sink signature for honeypots: sink(event)
    def sink(self) -> Callable[[Event], None]:
        def _sink(event: Event) -> None:
            self.handle(event)
        return _sink
