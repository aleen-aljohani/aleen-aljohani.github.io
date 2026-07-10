# Architecture

## 1. Overview

SmartHoneyNet is a modular detection platform. Where the original graduation
project wired together three virtual machines by hand, this rebuild expresses
the same architecture as composable software components plus an optional
container deployment.

```
┌──────────────┐   TCP/telnet    ┌───────────────────┐
│  Attacker    │────────────────▶│  TelnetHoneypot   │─┐
│  (simulators │   HTTP          │  HttpHoneypot     │ │  Event
│   or real)   │────────────────▶│                   │ │  objects
└──────────────┘                 └───────────────────┘ │
                                                        ▼
                                          ┌─────────────────────────┐
                                          │        Pipeline         │
                                          │  (Logstash equivalent)  │
                                          └───────┬─────────┬───────┘
                             persist            │         │      JSON lines
                        ┌────────────────────────▼──┐   ┌──▼──────────────────┐
                        │        SQLite DB          │   │  logs/*.jsonl       │
                        │  (events, alerts)         │   │  → Filebeat/Logstash│
                        └───────────┬───────────────┘   │  → Elasticsearch    │
                                    │                   │  → Kibana dashboards│
                        ┌───────────▼───────────┐       └─────────────────────┘
                        │   DetectionEngine     │
                        │ signature + anomaly   │
                        │  → Alerts (+ MITRE)   │
                        └───────────┬───────────┘
                                    │
                        ┌───────────▼───────────┐
                        │      Analyzer         │
                        │  reports (md / json)  │
                        └───────────────────────┘
```

## 2. Components

### 2.1 Honeypots (`honeynet.honeypots`)
Low-interaction sensors emulating vulnerable smart-home devices.

- **TelnetHoneypot** — a Mirai-style IoT hub. Presents a BusyBox banner and
  `login:`/`Password:` prompts, records every credential pair, "accepts"
  known-weak credentials to lure the attacker into a fake shell, and logs the
  commands they type. No command is ever executed.
- **HttpHoneypot** — a "SmartHome Hub 2.4" web admin panel. Records every
  request (method, path, user-agent, POST credentials) and returns static
  HTML. Feeds the DoS, scanning and injection rules.

Both are threaded servers that push `Event` objects to a sink callback. This
decoupling means the same sensors work in tests, the demo, and production.

### 2.2 Pipeline (`honeynet.pipeline`)
The software equivalent of Logstash. For every event it (1) persists to
SQLite, (2) appends a JSON line for the ELK ingest path, (3) runs the
detection engine, and (4) persists and dispatches any alerts.

### 2.3 Detection engine (`honeynet.detection.engine`)
A **hybrid IDS**:

- *Signature-based:* Mirai default-credential set, IoT web-exploitation URL
  patterns, and shell command-injection payloads.
- *Anomaly / threshold-based:* per-source sliding windows that flag
  brute-force, DoS and port-scan behaviour by rate.

A per-`(source, rule)` cooldown collapses sustained attacks into single,
actionable alerts. Every alert carries a MITRE ATT&CK technique
(`honeynet.mitre`).

### 2.4 Storage
- **SQLite** (`honeynet.database`) is the local system of record — a real,
  transactional, indexed, queryable database with zero ops overhead.
- **Elasticsearch** provides the same in the full deployment; the index
  template lives in `config/elasticsearch/`.

### 2.5 Analysis & reporting (`honeynet.analysis`)
Aggregates the store into attack categories, top offenders, credential
intelligence, targeted ports, a MITRE breakdown and an hourly timeline, then
renders Markdown or JSON reports. Kibana provides the interactive equivalent.

## 3. Data model

`Event` and `Alert` (`honeynet.models`) are the two records that flow through
the system. They serialise identically to a SQLite row and to the JSON that
Elasticsearch indexes, so the local and ELK paths stay consistent. See the
Elasticsearch mapping in `config/elasticsearch/honeynet-events-template.json`
for field types.

## 4. Design decisions

| Decision | Rationale |
|---|---|
| Standard-library core | Runs anywhere, trivial CI, no supply-chain surface |
| Telnet as the IoT sensor | It is *the* Mirai vector — most faithful smart-home threat model |
| SQLite **and** ELK | The pipeline is fully testable offline; ELK adds scale + dashboards |
| Sink-callback sensors | Same honeypots serve tests, demo and production unchanged |
| Safety enforced in code | Ethics as a hard control, not just documentation |
| MITRE mapping | Turns raw alerts into standardised, analyst-ready intelligence |

## 5. Mapping to the original three-VM design

| Original VM | SmartHoneyNet equivalent |
|---|---|
| Attacker VM (Parrot OS) | `honeynet.attacks` simulators (safety-gated) |
| Honeypot VM (Cowrie, Pentbox) | `TelnetHoneypot` + `HttpHoneypot` containers |
| IDS + ELK VM (Snort, ELK) | `DetectionEngine` + `config/suricata` + ELK compose services |
