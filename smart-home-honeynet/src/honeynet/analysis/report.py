"""Render an :class:`AnalysisSummary` as Markdown or JSON."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .analyzer import AnalysisSummary


def render_json(summary: AnalysisSummary, indent: int = 2) -> str:
    return json.dumps(summary.to_dict(), indent=indent)


def _table(rows: list, headers: tuple[str, ...]) -> str:
    if not rows:
        return "_No data._\n"
    out = ["| " + " | ".join(headers) + " |",
           "| " + " | ".join("---" for _ in headers) + " |"]
    for row in rows:
        cells = row if isinstance(row, (list, tuple)) else (row,)
        out.append("| " + " | ".join(str(c) for c in cells) + " |")
    return "\n".join(out) + "\n"


def render_markdown(summary: AnalysisSummary, title: str = "SmartHoneyNet — Threat Analysis Report") -> str:
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    parts: list[str] = []
    parts.append(f"# {title}\n")
    parts.append(f"_Generated: {now}_\n")

    parts.append("## 1. Executive summary\n")
    parts.append(_table([
        ("Total events captured", summary.total_events),
        ("Total alerts raised", summary.total_alerts),
        ("Unique source addresses", summary.unique_sources),
        ("Distinct attack categories", len(summary.alert_categories)),
    ], ("Metric", "Value")))

    parts.append("## 2. Alerts by category\n")
    parts.append(_table(summary.alert_categories, ("Category", "Count")))

    parts.append("## 3. Alerts by severity\n")
    parts.append(_table(summary.severities, ("Severity", "Count")))

    parts.append("## 4. MITRE ATT&CK techniques observed\n")
    parts.append(_table(summary.mitre_techniques, ("Technique", "Name", "Count")))

    parts.append("## 5. Top source addresses\n")
    parts.append(_table(summary.top_sources, ("Source IP", "Events")))

    parts.append("## 6. Credential intelligence\n")
    parts.append("### 6.1 Most-tried credential pairs\n")
    parts.append(_table(summary.top_credentials, ("username:password", "Count")))
    parts.append("### 6.2 Most-tried usernames\n")
    parts.append(_table(summary.top_usernames, ("Username", "Count")))
    parts.append("### 6.3 Most-tried passwords\n")
    parts.append(_table(summary.top_passwords, ("Password", "Count")))

    parts.append("## 7. Targeted ports\n")
    parts.append(_table(summary.targeted_ports, ("Port", "Events")))

    parts.append("## 8. Suspicious HTTP paths\n")
    parts.append(_table(summary.top_paths, ("Path", "Count")))

    parts.append("## 9. Commands captured in honeypot shells\n")
    parts.append(_table(summary.top_commands, ("Command", "Count")))

    parts.append("## 10. Activity timeline (hourly)\n")
    parts.append(_table(summary.timeline, ("Hour (UTC)", "Events")))

    return "\n".join(parts)
