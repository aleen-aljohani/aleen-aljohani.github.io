"""Runtime configuration and detection thresholds.

Defaults are defined in code so the system works with zero external files;
they can be overridden from a YAML file (``config/detection_rules.yaml``)
when present.  PyYAML is optional — if it is not installed the built-in
defaults are used.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any, Optional

# --- Mirai / IoT default credential pairs frequently seen in the wild -------
# Used both to seed the honeypot's "weak" accounts and to flag the
# "default-credentials" detection category.
MIRAI_DEFAULT_CREDENTIALS: list[tuple[str, str]] = [
    ("root", "xc3511"),
    ("root", "vizxv"),
    ("root", "admin"),
    ("admin", "admin"),
    ("root", "root"),
    ("root", "12345"),
    ("guest", "guest"),
    ("admin", "password"),
    ("root", "888888"),
    ("support", "support"),
    ("admin", "1234"),
    ("root", "default"),
]

# HTTP paths that indicate scanning / exploitation of IoT web interfaces.
SUSPICIOUS_HTTP_PATTERNS: list[str] = [
    r"/cgi-bin/",
    r"\.\./",              # path traversal
    r"/boaform/",          # common IoT router admin
    r"/HNAP1",             # D-Link exploitation
    r"/setup\.cgi",
    r"/shell",
    r"/wget",
    r"/GponForm/",
    r"/dvr",
    r"/(?:etc/passwd|proc/self)",
]

# Shell metacharacters / payloads that suggest command injection.
INJECTION_PATTERNS: list[str] = [
    r";\s*(?:wget|curl|tftp|busybox|chmod|sh)\b",
    r"\|\s*sh\b",
    r"`[^`]+`",
    r"\$\([^)]+\)",
    r"&&\s*\w+",
    r"/bin/(?:busybox|sh)\b",
]


@dataclass
class DetectionConfig:
    """Thresholds for the sliding-window detection engine."""

    brute_force_threshold: int = 5          # failed logins ...
    brute_force_window: int = 60            # ... within N seconds

    dos_threshold: int = 50                 # requests/connections ...
    dos_window: int = 10                    # ... within N seconds

    port_scan_threshold: int = 8            # distinct ports ...
    port_scan_window: int = 30              # ... within N seconds

    alert_cooldown: int = 30                # suppress duplicate alerts per rule/ip

    mirai_credentials: list[tuple[str, str]] = field(
        default_factory=lambda: list(MIRAI_DEFAULT_CREDENTIALS)
    )
    suspicious_http_patterns: list[str] = field(
        default_factory=lambda: list(SUSPICIOUS_HTTP_PATTERNS)
    )
    injection_patterns: list[str] = field(
        default_factory=lambda: list(INJECTION_PATTERNS)
    )

    @classmethod
    def from_file(cls, path: str | os.PathLike[str]) -> "DetectionConfig":
        """Load overrides from a YAML/JSON file, falling back to defaults."""
        data = _load_mapping(Path(path))
        cfg = cls()
        for f in fields(cls):
            if f.name in data and data[f.name] is not None:
                value = data[f.name]
                if f.name == "mirai_credentials":
                    value = [tuple(pair) for pair in value]
                setattr(cfg, f.name, value)
        return cfg


@dataclass
class Settings:
    """Top-level service configuration (env-overridable)."""

    telnet_host: str = "127.0.0.1"
    telnet_port: int = 2323
    http_host: str = "127.0.0.1"
    http_port: int = 8080
    database_path: str = "honeynet.db"
    events_jsonl: Optional[str] = "logs/events.jsonl"   # Filebeat/Logstash input
    alerts_jsonl: Optional[str] = "logs/alerts.jsonl"
    detection_rules_path: Optional[str] = "config/detection_rules.yaml"

    @classmethod
    def from_env(cls, **overrides: Any) -> "Settings":
        s = cls()
        env_map = {
            "telnet_host": "HONEYNET_TELNET_HOST",
            "telnet_port": "HONEYNET_TELNET_PORT",
            "http_host": "HONEYNET_HTTP_HOST",
            "http_port": "HONEYNET_HTTP_PORT",
            "database_path": "HONEYNET_DB",
            "events_jsonl": "HONEYNET_EVENTS_JSONL",
            "alerts_jsonl": "HONEYNET_ALERTS_JSONL",
            "detection_rules_path": "HONEYNET_RULES",
        }
        for attr, env in env_map.items():
            if env in os.environ:
                raw = os.environ[env]
                current = getattr(s, attr)
                setattr(s, attr, int(raw) if isinstance(current, int) else raw)
        for k, v in overrides.items():
            setattr(s, k, v)
        return s

    def load_detection_config(self) -> DetectionConfig:
        if self.detection_rules_path and Path(self.detection_rules_path).exists():
            return DetectionConfig.from_file(self.detection_rules_path)
        return DetectionConfig()


def _load_mapping(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore

        return yaml.safe_load(text) or {}
    except ModuleNotFoundError:
        # Fall back to JSON so the file remains usable without PyYAML.
        import json

        try:
            return json.loads(text)
        except ValueError:
            return {}
