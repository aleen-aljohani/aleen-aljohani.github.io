"""Wiring that assembles the full sensor -> pipeline -> IDS -> store stack."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .config import Settings
from .database import Database
from .detection.engine import DetectionEngine
from .honeypots import HttpHoneypot, TelnetHoneypot
from .models import Alert
from .pipeline import Pipeline


@dataclass
class HoneyNet:
    """A running honeynet: two honeypots feeding one detection pipeline."""

    settings: Settings
    db: Database
    pipeline: Pipeline
    telnet: TelnetHoneypot
    http: HttpHoneypot

    @classmethod
    def build(cls, settings: Optional[Settings] = None,
              on_alert=None) -> "HoneyNet":
        settings = settings or Settings.from_env()
        db = Database(settings.database_path)
        engine = DetectionEngine(settings.load_detection_config())
        pipeline = Pipeline(
            db=db,
            engine=engine,
            events_jsonl=settings.events_jsonl,
            alerts_jsonl=settings.alerts_jsonl,
            on_alert=on_alert or _default_alert_sink,
        )
        sink = pipeline.sink()
        telnet = TelnetHoneypot(settings.telnet_host, settings.telnet_port, sink)
        http = HttpHoneypot(settings.http_host, settings.http_port, sink)
        return cls(settings, db, pipeline, telnet, http)

    def start(self) -> "HoneyNet":
        self.telnet.start()
        self.http.start()
        return self

    def stop(self) -> None:
        self.telnet.stop()
        self.http.stop()
        self.db.close()


def _default_alert_sink(alert: Alert) -> None:
    print(
        f"[ALERT] {alert.severity.upper():8} {alert.category:20} "
        f"{alert.source_ip:15} {alert.mitre_technique or '-':10} {alert.description}"
    )
