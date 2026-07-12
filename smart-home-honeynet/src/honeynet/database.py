"""SQLite persistence layer for events, alerts and derived statistics.

SQLite gives the project a real, transactional, queryable database with zero
operational overhead — it is the local system of record that mirrors what
Elasticsearch stores in a full ELK deployment.  A single shared connection
guarded by a lock makes it safe to use from the honeypot worker threads.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterable, Optional

from .models import Alert, Event

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id     TEXT PRIMARY KEY,
    timestamp    TEXT NOT NULL,
    honeypot     TEXT NOT NULL,
    event_type   TEXT NOT NULL,
    source_ip    TEXT NOT NULL,
    source_port  INTEGER,
    dest_port    INTEGER,
    protocol     TEXT,
    session_id   TEXT,
    username     TEXT,
    password     TEXT,
    command      TEXT,
    http_method  TEXT,
    http_path    TEXT,
    user_agent   TEXT,
    payload_size INTEGER DEFAULT 0,
    success      INTEGER DEFAULT 0,
    raw          TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id        TEXT PRIMARY KEY,
    timestamp       TEXT NOT NULL,
    rule_id         TEXT NOT NULL,
    category        TEXT NOT NULL,
    severity        TEXT NOT NULL,
    source_ip       TEXT NOT NULL,
    description     TEXT,
    honeypot        TEXT,
    event_count     INTEGER DEFAULT 1,
    mitre_technique TEXT,
    mitre_name      TEXT,
    first_seen      TEXT,
    last_seen       TEXT,
    raw             TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_category ON alerts(category);
"""

_EVENT_COLUMNS = [
    "event_id", "timestamp", "honeypot", "event_type", "source_ip",
    "source_port", "dest_port", "protocol", "session_id", "username",
    "password", "command", "http_method", "http_path", "user_agent",
    "payload_size", "success", "raw",
]

_ALERT_COLUMNS = [
    "alert_id", "timestamp", "rule_id", "category", "severity", "source_ip",
    "description", "honeypot", "event_count", "mitre_technique", "mitre_name",
    "first_seen", "last_seen", "raw",
]


class Database:
    """Thread-safe SQLite wrapper for the honeynet."""

    def __init__(self, path: str = ":memory:") -> None:
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    # -- writes ------------------------------------------------------------
    def insert_event(self, event: Event) -> None:
        row = event.to_dict()
        row["success"] = 1 if row["success"] else 0
        row["raw"] = json.dumps(row["raw"], separators=(",", ":"))
        with self._lock:
            self._conn.execute(
                f"INSERT OR REPLACE INTO events ({','.join(_EVENT_COLUMNS)}) "
                f"VALUES ({','.join('?' for _ in _EVENT_COLUMNS)})",
                [row[c] for c in _EVENT_COLUMNS],
            )
            self._conn.commit()

    def insert_alert(self, alert: Alert) -> None:
        row = alert.to_dict()
        row["raw"] = json.dumps(row["raw"], separators=(",", ":"))
        with self._lock:
            self._conn.execute(
                f"INSERT OR REPLACE INTO alerts ({','.join(_ALERT_COLUMNS)}) "
                f"VALUES ({','.join('?' for _ in _ALERT_COLUMNS)})",
                [row[c] for c in _ALERT_COLUMNS],
            )
            self._conn.commit()

    # -- reads -------------------------------------------------------------
    def _query(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute(sql, tuple(params)).fetchall())

    def get_events(self, limit: Optional[int] = None) -> list[Event]:
        sql = "SELECT * FROM events ORDER BY timestamp"
        if limit:
            sql += f" LIMIT {int(limit)}"
        return [Event.from_dict(dict(r)) for r in self._query(sql)]

    def get_alerts(self, limit: Optional[int] = None) -> list[Alert]:
        sql = "SELECT * FROM alerts ORDER BY timestamp"
        if limit:
            sql += f" LIMIT {int(limit)}"
        return [Alert.from_dict(dict(r)) for r in self._query(sql)]

    def count_events(self) -> int:
        return int(self._query("SELECT COUNT(*) AS c FROM events")[0]["c"])

    def count_alerts(self) -> int:
        return int(self._query("SELECT COUNT(*) AS c FROM alerts")[0]["c"])

    def top(self, column: str, table: str = "events", limit: int = 10,
            where: str = "") -> list[tuple[str, int]]:
        """Generic top-N aggregation, e.g. top source_ip / username.

        ``column``/``table`` are validated against an allow-list so this
        internal query builder cannot be turned into an injection vector.
        """
        if column not in _EVENT_COLUMNS + _ALERT_COLUMNS:
            raise ValueError(f"unknown column {column!r}")
        if table not in ("events", "alerts"):
            raise ValueError(f"unknown table {table!r}")
        conditions = [f"{column} IS NOT NULL"]
        if where:
            conditions.append(f"({where})")
        clause = " AND ".join(conditions)
        rows = self._query(
            f"SELECT {column} AS k, COUNT(*) AS c FROM {table} "
            f"WHERE {clause} "
            f"GROUP BY {column} ORDER BY c DESC LIMIT {int(limit)}"
        )
        return [(r["k"], int(r["c"])) for r in rows]

    def category_counts(self) -> list[tuple[str, int]]:
        rows = self._query(
            "SELECT category AS k, COUNT(*) AS c FROM alerts "
            "GROUP BY category ORDER BY c DESC"
        )
        return [(r["k"], int(r["c"])) for r in rows]

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
