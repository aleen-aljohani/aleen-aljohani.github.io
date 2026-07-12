# Changelog

## v2.0
A reproducible, tested and containerised platform for hunting, detecting and
analysing attacks on smart-home / IoT networks:

- Low-interaction Telnet and HTTP honeypots emulating vulnerable IoT devices.
- Hybrid signature + anomaly detection engine covering six attack categories,
  with MITRE ATT&CK mapping on every alert.
- SQLite system-of-record plus an ELK ingest pipeline and Kibana dashboards.
- 39 automated tests (~84% coverage) and CI on Python 3.9/3.11/3.12.
- A labelled evaluation harness (100% precision/recall, 0 benign false
  positives).
- Safety-gated attack simulators that refuse any non-private target.
- Threat model, security controls, deployment/runbook docs and an IEEE-style
  report (Markdown, Word and PDF).
