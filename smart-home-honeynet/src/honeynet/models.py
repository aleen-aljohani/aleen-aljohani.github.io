"""Core data models: honeypot events and detection alerts.

Both models are plain dataclasses with helpers to convert to/from JSON and
sqlite rows.  Keeping them dependency-free makes them trivial to serialise
onto the ELK pipeline (as JSON) *and* into the local SQLite store.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


def utcnow_iso() -> str:
    """Return an ISO-8601 UTC timestamp (matches @timestamp used by ELK)."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def new_id() -> str:
    return uuid.uuid4().hex


class EventType:
    """Canonical honeypot event types."""

    CONNECTION = "connection"
    LOGIN_ATTEMPT = "login_attempt"
    COMMAND = "command"
    HTTP_REQUEST = "http_request"
    DISCONNECT = "disconnect"


class Severity:
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Event:
    """A single observation captured by a honeypot sensor."""

    source_ip: str
    honeypot: str
    event_type: str
    event_id: str = field(default_factory=new_id)
    timestamp: str = field(default_factory=utcnow_iso)
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    protocol: str = "tcp"
    session_id: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    command: Optional[str] = None
    http_method: Optional[str] = None
    http_path: Optional[str] = None
    user_agent: Optional[str] = None
    payload_size: int = 0
    success: bool = False
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Event":
        raw = data.get("raw")
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except (ValueError, TypeError):
                raw = {"value": raw}
        known = {f: data.get(f) for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        known["raw"] = raw or {}
        # sqlite stores booleans as 0/1
        known["success"] = bool(known.get("success"))
        return cls(**{k: v for k, v in known.items() if v is not None or k in ("raw",)})


@dataclass
class Alert:
    """A detection produced by the IDS engine from one or more events."""

    rule_id: str
    category: str
    severity: str
    source_ip: str
    description: str
    alert_id: str = field(default_factory=new_id)
    timestamp: str = field(default_factory=utcnow_iso)
    honeypot: Optional[str] = None
    event_count: int = 1
    mitre_technique: Optional[str] = None
    mitre_name: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Alert":
        raw = data.get("raw")
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except (ValueError, TypeError):
                raw = {"value": raw}
        known = {f: data.get(f) for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        known["raw"] = raw or {}
        return cls(**{k: v for k, v in known.items() if v is not None or k in ("raw",)})
