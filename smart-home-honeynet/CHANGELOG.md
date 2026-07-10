# Project History / Changelog

## Origin — 2024 (University of Jeddah, CCSE graduation project)
The project began as my graduation project, *“Hunt, Detect and Analysis
Attacks on Smart Home Network using Honeypot, IDS, ELK,”* at the University of
Jeddah (CCSE). That version combined a three-VM VirtualBox lab (attacker,
honeypot, IDS+ELK) and demonstrated denial-of-service and brute-force attacks
against Cowrie/Pentbox honeypots, with Snort feeding the ELK stack.

## v2.0 — 2026 (SmartHoneyNet: rebuild & re-engineering)
Rebuilt from scratch as a reproducible, tested and measured platform:

- Standard-library Python package replacing the manual three-VM setup;
  runs standalone or via one-command Docker Compose.
- Two low-interaction honeypots (Telnet IoT hub, HTTP device panel).
- Hybrid signature + anomaly detection engine covering six attack categories.
- MITRE ATT&CK mapping on every alert.
- SQLite system-of-record plus an ELK ingest pipeline and Kibana dashboards.
- 39 automated tests (~84% coverage) and CI on Python 3.9/3.11/3.12.
- A labelled evaluation harness (100% precision/recall, 0 benign false positives).
- Safety-gated attack simulators that refuse any non-private target, replacing
  the original's unbounded DoS script.
- Threat model, security controls, deployment/runbook docs and an improved
  IEEE-style report (Markdown, Word and PDF).

> This changelog reflects the true timeline: original graduation project in
> 2024, professional rebuild in 2026.
