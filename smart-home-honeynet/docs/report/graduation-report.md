# Hunt, Detect and Analyse Attacks on a Smart-Home Network using Honeypots, an IDS and the ELK Stack

**An improved and reproducible re-engineering of the CCSE graduation project.**

Aleen Saleh Aljohani — aleensaljohani@gmail.com
Cybersecurity Department, College of Computer Science and Engineering (CCSE), University of Jeddah

---

## Abstract

Smart homes are now mainstream: the number of smart-home households is
projected to grow to roughly **312 million by 2027**, an increase of over
86 % versus 2023. This convenience comes with a large, poorly-defended attack
surface — IoT devices ship with default credentials, exposed telnet/HTTP
management interfaces and unpatched firmware, and are the primary recruiting
ground for botnets such as Mirai. The original *Hunt, Detect and Analysis
Attacks on Smart Home Network* project demonstrated that a combination of
**honeypots**, an **intrusion-detection system (IDS)** and the **ELK stack**
can capture and study these attacks. However, that work was delivered as a
manually-provisioned, three-VM lab that demonstrated two attacks
qualitatively and could not be reproduced, tested or measured by a third
party.

This report presents **SmartHoneyNet**, a complete redesign and rebuild of
the same idea as a *reproducible, tested and quantitatively evaluated*
security platform. Two low-interaction honeypots emulate a Mirai-style telnet
IoT hub and a smart-home device web panel; a hybrid signature-plus-anomaly
detection engine classifies six attack categories and maps every alert to
**MITRE ATT&CK**; a pipeline persists all data to both a local SQLite
database and to Elasticsearch for Kibana visualisation. The whole platform
runs on a single host with `docker compose up`, ships with a **38-test
automated suite**, and includes explicit **security and ethics controls** —
most notably attack simulators that are hard-blocked from targeting any
non-private address. On a controlled, labelled evaluation set the engine
achieves **100 % precision and recall with zero false positives on benign
traffic**. We discuss the design, the measured results, the remaining
limitations of a software-only honeynet, and a concrete roadmap toward the
smart-home-specific honeypots the original project envisioned.

**Index Terms** — Honeypot, IoT security, Intrusion Detection, ELK Stack,
Mirai, MITRE ATT&CK, Smart Home, Threat Hunting.

---

## 1. Introduction

Interconnected "smart" devices — thermostats, cameras, locks, plugs and hubs
— have woven themselves into the modern home. Each device is a small networked
computer, and collectively they form a network whose weakest member sets the
security of the whole. The defensive problem is asymmetric: a homeowner has
neither the tooling nor the expertise of an enterprise SOC, yet faces the same
internet-wide automated adversaries.

The word **"Hunt"** in the project title captures the intended posture: not
merely to block attacks reactively, but to *attract, observe and understand*
them. A honeypot deliberately exposes an attractive, instrumented target;
whatever an attacker does to it is, by definition, malicious and worth
studying. Pairing honeypots with an IDS and a log-analytics stack turns those
observations into detections and, ultimately, into intelligence.

### 1.1 Problem statement

Smart-home networks are attacked continuously by automated botnets and
scanners, but homeowners lack visibility into these attacks and researchers
lack reproducible platforms for studying them in a smart-home context.

### 1.2 Aim and objectives

**Aim.** To build a reproducible platform that hunts, detects and analyses
attacks against a smart-home network, and to evaluate its detection
effectiveness.

**Objectives.**
1. Emulate vulnerable smart-home devices with honeypots that safely capture
   attacker behaviour.
2. Implement an IDS that detects the dominant smart-home attack classes in
   real time using both signatures and behavioural anomalies.
3. Integrate an ELK pipeline (and an offline database) for storage,
   classification and visualisation of captured attacks.
4. **Measure** detection performance quantitatively, not just qualitatively.
5. Enforce responsible-use controls so the platform cannot be weaponised.

### 1.3 Contributions over the original project

| # | Original project | This work |
|---|---|---|
| 1 | 3 manually-built VirtualBox VMs | One-command `docker compose` + pure-Python standalone mode |
| 2 | 2 attacks shown via screenshots | 6 detection categories, each unit-tested |
| 3 | Qualitative results only | **Quantitative evaluation** (precision/recall/F1) |
| 4 | Snort signatures only | **Hybrid** signature + rate-based anomaly engine |
| 5 | No attack classification taxonomy | **MITRE ATT&CK** mapping on every alert |
| 6 | No automated testing | **38 automated tests** + CI on 3 Python versions |
| 7 | Attack script was an unbounded DoS loop | Bounded, **safety-gated** simulators (private targets only) |
| 8 | No threat model / security controls | Documented threat model + enforced security controls |
| 9 | Not reproducible | Fully reproducible; deterministic evaluation harness |

---

## 2. Background

### 2.1 Smart-home networks and their risks
A smart home links appliances and sensors to a hub/router, typically
controlled through a web or mobile interface. Representative risks include
**data and identity theft** from unprotected devices, **eavesdropping** on
device traffic, and **(distributed) denial-of-service** — the last amplified
by the sheer number of weakly-protected IoT devices available for recruitment.

### 2.2 Honeypots
A honeypot is a deception asset: an intentionally exposed, instrumented system
whose only purpose is to be attacked so defenders can study the attacker. They
are classified by interaction level. **Low-interaction** honeypots (used here)
emulate just enough of a service to capture intent while never executing
attacker input — a deliberate safety property. **High-interaction** honeypots
expose real systems and yield richer data at much higher risk.

### 2.3 Intrusion Detection Systems
An IDS monitors activity and raises alerts on suspicious behaviour.
**Signature-based** detection matches known-bad patterns — precise for known
threats but blind to novel ones. **Anomaly-based** detection models normal
behaviour and flags deviations — able to catch new attacks at the cost of
more false positives. SmartHoneyNet deliberately combines both.

### 2.4 The ELK stack
**Elasticsearch** stores and indexes events for fast search; **Logstash**
ingests, parses and enriches incoming data; **Kibana** visualises it as
dashboards. ELK is a cost-effective, open-source alternative to commercial
SIEMs (Splunk, QRadar, ArcSight) and is well suited to honeypot log analytics.

### 2.5 Mirai and IoT botnets
Mirai and its descendants scan the internet for devices with open telnet
(TCP 23) and try a small list of factory-default credentials (e.g.
`root:xc3511`, `root:vizxv`, `admin:admin`). This single behaviour accounts
for a large share of real IoT compromise, which is why an accurate telnet
honeypot and a default-credential signature sit at the centre of this design.

---

## 3. Related Work

Five prior studies frame this project. The comparison below preserves the
original survey and adds the gap each leaves open.

| Ref | Year | Approach | Result | Limitation |
|---|---|---|---|---|
| [10] | 2021 | ML attack classification on IoT (Bot-IoT) | Random Forest best for binary, KNN for multi-class | No real-time/streaming evaluation |
| [11] | 2021 | Threat hunting with the Elastic stack | ELK is a cost-effective hunting tool | Needs human input + extra controls |
| [12] | 2021 | Honeynet + network-flow classification for IoT botnets | Successful botnet detection via traffic analysis | Limited algorithm comparison |
| [13] | 2020 | IoT + Docker honeypots (Cowrie) | Default creds match Mirai; most attacks from Europe | Not all IoT attack types covered |
| [14] | 2019 | Malicious-event detection with ELK + CTI | Detects & prioritises most threats | False positives; manual cleanup |

**Difference from existing work.** Like [13] we use honeypots feeding ELK, and
like [11] we use ELK for hunting — but SmartHoneyNet is distinguished by (a) a
*hybrid* detection engine combining signatures and behavioural thresholds,
(b) an explicit **MITRE ATT&CK** classification of every alert, (c) a fully
**reproducible and automatically tested** implementation, and (d) a
**quantitative evaluation** with published precision/recall — addressing the
"qualitative only" and "not reproducible" gaps common to the surveyed work.

---

## 4. Threat Model

The full threat model is in [`../threat-model.md`](../threat-model.md); its
essence:

- **Assets:** device credentials, camera/sensor feeds, device compute and
  bandwidth, and the LAN foothold itself.
- **Adversaries:** automated IoT botnets (Mirai-class), opportunistic
  internet-wide scanners, and manual attackers.
- **Trust boundary:** the honeynet lives on an isolated segment that is
  untrusted inbound and has **no egress**; ELK management binds to localhost.

Attacker goals are expressed directly as MITRE ATT&CK techniques, each paired
with the rule that detects it (Table in §6.2).

---

## 5. Methodology

The project follows the same three-stage data flow as the original
(generate → collect → analyse), re-expressed as software stages:

1. **Attack generation.** Adversary behaviour is produced either by real
   attackers (in a live deployment) or by the built-in, safety-gated
   simulators (in the lab/demo): port scan, telnet brute-force with IoT
   default credentials, HTTP request flood, and web-exploitation probes.
2. **Detection & collection.** Honeypots capture every interaction as a
   structured `Event`. A pipeline persists each event and runs it through the
   IDS engine, producing `Alert`s enriched with MITRE technique and severity.
3. **Transformation & analysis.** Events and alerts are written to SQLite and,
   in the full deployment, shipped through Logstash into Elasticsearch and
   visualised in Kibana. An analyzer produces Markdown/JSON threat reports.

This mirrors the original methodology while making every stage inspectable
and testable in isolation.

---

## 6. System Design

### 6.1 Architecture
The platform is a pipeline of composable components (full diagram in
[`../architecture.md`](../architecture.md)):

```
attacker → [telnet + http honeypots] → [pipeline] → SQLite + IDS engine → alerts
                                              └────→ JSON → Logstash → Elasticsearch → Kibana
                                                                              analyzer → reports
```

The original three VMs map cleanly onto software: the **attacker VM** becomes
the `attacks` simulators, the **honeypot VM** (Cowrie/Pentbox) becomes the
`TelnetHoneypot`/`HttpHoneypot` containers, and the **IDS+ELK VM**
(Snort + ELK) becomes the `DetectionEngine` (with an equivalent Suricata rule
file) plus the ELK compose services.

### 6.2 Detection rules and ATT&CK mapping

| Rule | Type | Category | MITRE | Trigger |
|---|---|---|---|---|
| `IOT-DEFAULT-CREDS` | signature | default-credentials | T1078.001 | Login using a known Mirai/IoT default pair |
| `SSH-TELNET-BRUTE-FORCE` | anomaly | brute-force | T1110.001 | ≥5 failed logins / 60 s from one source |
| `HTTP-DOS-FLOOD` | anomaly | denial-of-service | T1498 | ≥50 requests / 10 s from one source |
| `PORT-SCAN` | anomaly | reconnaissance | T1046 | ≥8 distinct ports / 30 s from one source |
| `SUSPICIOUS-HTTP-PATH` | signature | active-scanning | T1595.002 | IoT exploit URL (boaform, HNAP1, traversal, …) |
| `CMD-INJECTION` | signature | command-injection | T1059 | Shell payload (`;wget`, `busybox`, backticks, …) |

A per-`(source, rule)` **cooldown** collapses a sustained campaign into a
single actionable alert instead of thousands of duplicates.

### 6.3 Data model and storage
Two records flow through the system — `Event` (an observation) and `Alert` (a
detection). They serialise identically to a SQLite row and to the JSON
Elasticsearch indexes, keeping the offline and ELK paths consistent. SQLite is
the local system of record (transactional, indexed, queryable); Elasticsearch
provides the same at scale with Kibana dashboards. The Elasticsearch mapping
types `source_ip` as `ip` and `geo.location` as `geo_point` for map
visualisations.

---

## 7. Implementation

The core is implemented in **Python using only the standard library** (PyYAML
optional), which makes it portable, auditable and trivial to test.

- **Telnet honeypot** — a threaded TCP server presenting a BusyBox banner and
  `login:`/`Password:` prompts. It strips telnet IAC negotiation bytes,
  records each credential pair, "accepts" known-weak credentials to lure the
  attacker into a **fake** shell, and logs typed commands. It never executes
  anything and bounds attempts, commands and session time.
- **HTTP honeypot** — a threaded HTTP server emulating a "SmartHome Hub 2.4"
  admin panel; records method, path, user-agent and POSTed credentials, caps
  request-body size, and returns only static HTML.
- **Detection engine** — maintains per-source sliding-window deques for the
  rate rules and compiled regex sets for the signature rules; thread-safe and
  stream-oriented.
- **Pipeline** — persists to SQLite, appends JSON lines for Logstash, runs the
  engine and dispatches alerts.
- **Attack simulators** — port scan, brute-force and a **bounded** HTTP flood
  (a safe re-implementation of the original's unbounded `while True` DoS
  script), each gated by the safety module.
- **Analyzer & CLI** — aggregate the store and expose `serve`, `demo`,
  `attack` and `analyze` sub-commands.

### 7.1 Deployment
`docker compose up -d --build` starts the honeypots plus Elasticsearch,
Logstash and Kibana on an isolated bridge network; a saved-objects file
provisions the Kibana dashboards. A Suricata rule set mirrors the engine for
network-layer detection in a VM/hardware IDS.

---

## 8. Experiments and Evaluation

Two complementary experiments were run.

### 8.1 Experiment A — end-to-end demonstration
The `honeynet demo` command starts both honeypots on ephemeral ports and
launches, in sequence, a port scan, a telnet brute-force (wrong guesses +
IoT defaults), an HTTP flood and a set of web-exploitation probes against
them. A representative run captured **~196 events** and raised alerts in **all
five exercised categories** (default-credentials, brute-force,
denial-of-service, command-injection, active-scanning). This reproduces — and
extends from two to six attack types — the qualitative demonstration of the
original project, but as a single reproducible command.

### 8.2 Experiment B — quantitative detection evaluation
To measure detection quality we built a **labelled** event stream
(`scripts/evaluate.py`): 20 benign human-paced web requests, one benign strong
login, and four attack campaigns from distinct source addresses with known
ground-truth categories (94 events total). Metrics are computed at
**source-campaign granularity**, which matches how the rate rules are designed
to fire (once per campaign, not once per packet).

**Results.**

| Category | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| default-credentials | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| brute-force | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| denial-of-service | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| active-scanning | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| command-injection | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| **Micro-average** | | | | **1.00** | **1.00** | **1.00** |

Benign sources: 2 — **false positives: 0**.

The engine detected every attack campaign in its correct category and raised
**no alerts on benign traffic** in this controlled set. These numbers describe
a *clean, labelled* set and are asserted by a regression test
(`tests/test_evaluation.py`); §10 is candid about why real-world traffic is
harder.

### 8.3 Automated test suite
**38 tests** (pytest) cover the database, every detection rule with explicit
synthetic timelines, live honeypot interaction, the safety guardrails, the
pipeline, the analyzer, the CLI and a full in-process integration run;
line coverage is **~84 %**. CI runs the suite plus the demo on Python 3.9,
3.11 and 3.12.

---

## 9. Results and Discussion

The experiments confirm the original hypothesis — that honeypots + IDS + ELK
form an effective, low-cost smart-home detection stack — and strengthen it
with measurement. Three findings stand out:

1. **Default credentials remain the highest-signal indicator.** A single
   login with a Mirai default pair is immediately and unambiguously malicious,
   corroborating [13]. This makes the `IOT-DEFAULT-CREDS` signature the most
   valuable single rule for a smart-home context.
2. **Hybrid detection is complementary, not redundant.** Signatures caught the
   *known* (default creds, exploit URLs, injection payloads) with high
   precision; rate-based anomaly rules caught *behaviour* (brute-force, DoS,
   scanning) that has no fixed signature. Neither approach alone covers the
   set.
3. **The credential intelligence has defensive value.** Aggregating the
   captured username/password attempts (the analyzer's credential report)
   directly yields a blocklist of the passwords a homeowner must never use —
   turning attack data into actionable hardening advice.

---

## 10. Security, Ethics and Limitations

### 10.1 Responsible-use controls
Because the project ships attack tooling, ethics are enforced *in code*, not
merely documented:

- Simulators call `assert_safe_target()`, which resolves the target and
  refuses (`SafetyError`) unless **every** address is loopback/RFC-1918.
- The DoS simulator enforces hard caps on request count and duration.
- Honeypots are low-interaction: no shell, no execution, no payload storage,
  bounded buffers and session timeouts.
- Containers run non-root on an isolated network; ELK binds to localhost.

See [`../../SECURITY.md`](../../SECURITY.md) for the full control matrix.

### 10.2 Limitations
- **Software emulation, not silicon.** The honeypots emulate telnet/HTTP
  device interfaces; they do not reproduce full device firmware or non-IP
  radios (Zigbee/Z-Wave/BLE).
- **Controlled-set evaluation.** The perfect scores in §8.2 are on a clean
  labelled set. Production traffic — CDNs, health-checkers, NAT'd users —
  would produce false positives and demands threshold tuning; the framework
  supports this but the numbers would be lower and must be re-measured on real
  captures.
- **Rate rules need a warm-up window** and can miss "low-and-slow" attacks
  tuned below the thresholds.
- **Single-host port-scan visibility.** In the standalone demo only the two
  honeypot ports exist, so the `PORT-SCAN` rule is best exercised with
  synthetic multi-port events (as in the tests) or a multi-service deployment.

These are the honest boundaries within which the reported results hold —
addressing directly the original report's acknowledged limitations (the
unimplemented Pot2DPI honeypot and the Honeyd device-simulation crashes).

---

## 11. Future Work

1. **Cowrie / Dionaea integration** for higher-interaction SSH/telnet and
   malware capture, ingested through the same pipeline.
2. **An MQTT honeypot** (TCP 1883) — the dominant smart-home messaging broker,
   absent from the original design.
3. **A virtual IoT-device environment** (the original's Pot2DPI/Honeyd goal)
   emulating cameras, thermostats and locks with realistic fingerprints.
4. **ML-based anomaly detection** (e.g. the Random Forest / KNN approach of
   [10]) as a complementary engine, evaluated against the same labelled sets.
5. **GeoIP + threat-intel enrichment** in Logstash to attribute and map source
   campaigns, following [14].
6. **Automated response** — push high-severity source IPs to a firewall
   blocklist.

---

## 12. Conclusion

SmartHoneyNet re-engineers the *Hunt, Detect and Analysis Attacks on Smart
Home Network* project from a one-off, three-VM demonstration into a
reproducible, tested and measured security platform. It keeps the original's
sound core idea — honeypots to attract, an IDS to detect, and ELK to analyse —
and adds what a graduation project of this ambition needs to stand on its own:
a hybrid detection engine covering six attack classes, a MITRE ATT&CK
classification of every alert, a real database and dashboards, a 38-test
automated suite with CI, enforced security-and-ethics controls, and a
quantitative evaluation demonstrating 100 % precision and recall with zero
false positives on a controlled labelled set. As smart-home adoption races
toward hundreds of millions of households, tools that let defenders *hunt* the
attackers targeting them — safely, reproducibly and measurably — are exactly
what the field needs.

---

## References

[1] J. Lasquety-Reyes, "Global: Smart home — number of users 2018–2027,"
    Statista.
[2] "What is a smart home and what are the benefits?," Constellation.com.
[3] "Smart home: Threats and countermeasures," Rambus, 2017.
[4] "A Study of Smart Home Environment and its Security Threats," ResearchGate.
[5] "Smart home: Threats and countermeasures," Rambus, 2017.
[6] K. Subramanian and W. Meng, "Threat Hunting Using Elastic Stack: An
    Evaluation," IEEE SOLI, 2021, doi:10.1109/SOLI54607.2021.9672347.
[7] H. Qu, D. Qu and J. Tong, "Virtual environment for smart home," IEEE
    CYBER, 2015, doi:10.1109/CYBER.2015.7288113.
[8] "What is an intrusion detection system? Definition, types, and tools,"
    DNSstuff, 2019.
[9] E. Hasson and L. Cheng, "Honeypot," Imperva Learning Center.
[10] A. Churcher et al., "An experimental analysis of attack classification
     using machine learning in IoT networks," Sensors, 21(2):446, 2021.
[11] K. Subramanian and W. Meng, "Threat Hunting Using Elastic Stack," IEEE
     SOLI, 2021.
[12] Banerjee et al., "Network traffic analysis based IoT botnet detection
     using honeynet data," 2021.
[13] S. Bistarelli, E. Bosimini and F. Santini, "A Report on the Security of
     Home Connections with IoT and Docker Honeypots," CEUR-WS Vol-2597.
[14] M. Harikanth and P. Rajarajeswari, "Malicious event detection using ELK
     stack through cyber threat intelligence," IJITEE, 8(7):882–886, 2019.
[15] MITRE ATT&CK® — Enterprise Matrix. The MITRE Corporation.
[16] "Mirai (malware)" and the KrebsOnSecurity Mirai source-code analysis —
     default IoT credential lists.

---

*This report documents the SmartHoneyNet rebuild. All figures are reproducible
from this repository: `python3 -m honeynet demo` (Experiment A) and
`python3 scripts/evaluate.py` (Experiment B).*
