"""Threat-hunting analytics over the captured event/alert store.

This is the "Kibana" role in software form: it turns the raw records in the
database into the aggregations an analyst actually needs — attack categories,
top offenders, credential intelligence, an hourly timeline and a MITRE
ATT&CK breakdown.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from ..database import Database
from ..mitre import lookup


@dataclass
class AnalysisSummary:
    total_events: int = 0
    total_alerts: int = 0
    unique_sources: int = 0
    event_types: list[tuple[str, int]] = field(default_factory=list)
    alert_categories: list[tuple[str, int]] = field(default_factory=list)
    severities: list[tuple[str, int]] = field(default_factory=list)
    top_sources: list[tuple[str, int]] = field(default_factory=list)
    top_usernames: list[tuple[str, int]] = field(default_factory=list)
    top_passwords: list[tuple[str, int]] = field(default_factory=list)
    top_credentials: list[tuple[str, int]] = field(default_factory=list)
    top_paths: list[tuple[str, int]] = field(default_factory=list)
    top_commands: list[tuple[str, int]] = field(default_factory=list)
    targeted_ports: list[tuple[int, int]] = field(default_factory=list)
    mitre_techniques: list[tuple[str, str, int]] = field(default_factory=list)
    timeline: list[tuple[str, int]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "total_events": self.total_events,
            "total_alerts": self.total_alerts,
            "unique_sources": self.unique_sources,
            "event_types": self.event_types,
            "alert_categories": self.alert_categories,
            "severities": self.severities,
            "top_sources": self.top_sources,
            "top_usernames": self.top_usernames,
            "top_passwords": self.top_passwords,
            "top_credentials": self.top_credentials,
            "top_paths": self.top_paths,
            "top_commands": self.top_commands,
            "targeted_ports": self.targeted_ports,
            "mitre_techniques": self.mitre_techniques,
            "timeline": self.timeline,
        }


class Analyzer:
    def __init__(self, db: Database) -> None:
        self.db = db

    def summarize(self, top_n: int = 10) -> AnalysisSummary:
        events = self.db.get_events()
        alerts = self.db.get_alerts()

        s = AnalysisSummary()
        s.total_events = len(events)
        s.total_alerts = len(alerts)
        s.unique_sources = len({e.source_ip for e in events})

        s.event_types = Counter(e.event_type for e in events).most_common(top_n)
        s.top_sources = Counter(e.source_ip for e in events).most_common(top_n)

        usernames = Counter(e.username for e in events if e.username)
        passwords = Counter(e.password for e in events if e.password)
        creds = Counter(
            f"{e.username}:{e.password}"
            for e in events if e.username and e.password
        )
        s.top_usernames = usernames.most_common(top_n)
        s.top_passwords = passwords.most_common(top_n)
        s.top_credentials = creds.most_common(top_n)

        s.top_paths = Counter(e.http_path for e in events if e.http_path).most_common(top_n)
        s.top_commands = Counter(e.command for e in events if e.command).most_common(top_n)
        s.targeted_ports = Counter(
            e.dest_port for e in events if e.dest_port
        ).most_common(top_n)

        s.alert_categories = Counter(a.category for a in alerts).most_common(top_n)
        s.severities = Counter(a.severity for a in alerts).most_common()

        mitre_counter: Counter = Counter()
        for a in alerts:
            tech = lookup(a.category)
            mitre_counter[(tech.technique_id, tech.name)] += 1
        s.mitre_techniques = [
            (tid, name, count) for (tid, name), count in mitre_counter.most_common(top_n)
        ]

        s.timeline = self._hourly_timeline(events)
        return s

    @staticmethod
    def _hourly_timeline(events) -> list[tuple[str, int]]:
        buckets: Counter = Counter()
        for e in events:
            try:
                dt = datetime.fromisoformat(e.timestamp)
            except ValueError:
                continue
            buckets[dt.strftime("%Y-%m-%dT%H:00")] += 1
        return sorted(buckets.items())
