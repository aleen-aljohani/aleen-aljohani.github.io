#!/usr/bin/env python3
"""Render the IEEE report as a print-ready, two-column HTML page (7-8 pp).

Styled to approximate an IEEE conference paper with figures, code listings and
tables. Intended to be printed to PDF by headless Chromium. Output:
docs/report/SmartHoneyNet-IEEE.html
"""

from __future__ import annotations

from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "docs" / "report" / "SmartHoneyNet-IEEE.html"

CSS = """
@page { size: A4; margin: 18mm 16mm; }
* { box-sizing: border-box; }
body { font-family: 'Times New Roman', Times, serif; font-size: 10pt;
       line-height: 1.34; color: #000; margin: 0; }
.title-block { column-span: all; text-align: center; margin-bottom: 11pt; }
h1 { font-size: 20pt; margin: 0 0 5pt; line-height: 1.15; }
.subtitle { font-style: italic; font-size: 11.5pt; margin: 0 0 9pt; }
.authors { font-size: 10.5pt; margin: 2pt 0; }
.authors .email { font-size: 9pt; color: #222; }
.affil { font-size: 9pt; margin: 4pt 0 0; }
.body { column-count: 2; column-gap: 7mm; text-align: justify; }
h2 { font-size: 10pt; text-transform: uppercase; margin: 11pt 0 4pt;
     break-after: avoid; }
h3 { font-size: 10pt; font-style: italic; font-weight: normal;
     margin: 7pt 0 3pt; break-after: avoid; }
p { margin: 0 0 6pt; }
.abstract { font-style: italic; }
.abstract b, .keywords b { font-style: italic; }
ul { margin: 0 0 6pt 14pt; padding: 0; }
li { margin: 0 0 3pt; }
table { width: 100%; border-collapse: collapse; margin: 5pt 0 3pt;
        font-size: 8.4pt; break-inside: avoid; }
th, td { border: 0.5pt solid #000; padding: 2.5pt 3.5pt; text-align: left;
         vertical-align: top; }
th { background: #e8e8e8; text-align: center; font-weight: bold; }
caption, .figcap { caption-side: bottom; font-size: 8.4pt; font-style: italic;
          padding-top: 3pt; text-align: center; }
.refs { font-size: 8.5pt; }
.refs p { margin: 0 0 3pt; text-indent: -12pt; padding-left: 12pt; }
code { font-family: 'Consolas','Courier New',monospace; font-size: 9pt; }
pre { font-family: 'Consolas','Courier New',monospace; font-size: 8pt;
      line-height: 1.2; background: #f4f4f4; border: 0.5pt solid #bbb;
      padding: 5pt 6pt; margin: 4pt 0; white-space: pre-wrap; break-inside: avoid; }
figure { margin: 4pt 0; break-inside: avoid; text-align: center; }
figure svg { width: 100%; height: auto; }
.fw { column-span: all; }
.fw table { font-size: 8pt; }
"""

# ---- figures (inline SVG) -------------------------------------------------
FIG_ARCH = """
<svg viewBox="0 0 760 210" xmlns="http://www.w3.org/2000/svg" font-family="Times New Roman" font-size="12">
<defs><marker id="a" markerWidth="9" markerHeight="9" refX="7" refY="3" orient="auto">
<path d="M0,0 L7,3 L0,6 Z" fill="#000"/></marker></defs>
<rect x="8" y="80" width="96" height="44" rx="4" fill="#eef" stroke="#000"/>
<text x="56" y="98" text-anchor="middle">Attacker</text>
<text x="56" y="113" text-anchor="middle" font-size="10">(simulators)</text>
<rect x="140" y="60" width="110" height="86" rx="4" fill="#efe" stroke="#000"/>
<text x="195" y="80" text-anchor="middle">Honeypots</text>
<text x="195" y="98" text-anchor="middle" font-size="10">Telnet (2323)</text>
<text x="195" y="113" text-anchor="middle" font-size="10">HTTP (8080)</text>
<rect x="286" y="70" width="104" height="66" rx="4" fill="#ffe" stroke="#000"/>
<text x="338" y="92" text-anchor="middle">Pipeline</text>
<text x="338" y="108" text-anchor="middle" font-size="10">(Logstash-eq.)</text>
<rect x="424" y="18" width="112" height="42" rx="4" fill="#fee" stroke="#000"/>
<text x="480" y="35" text-anchor="middle" font-size="11">Detection engine</text>
<text x="480" y="50" text-anchor="middle" font-size="10">signature+anomaly</text>
<rect x="424" y="90" width="112" height="34" rx="4" fill="#eef" stroke="#000"/>
<text x="480" y="111" text-anchor="middle" font-size="11">SQLite store</text>
<rect x="424" y="150" width="112" height="40" rx="4" fill="#eef" stroke="#000"/>
<text x="480" y="166" text-anchor="middle" font-size="10">JSON lines</text>
<text x="480" y="181" text-anchor="middle" font-size="10">(events/alerts)</text>
<rect x="580" y="24" width="118" height="52" rx="4" fill="#efe" stroke="#000"/>
<text x="639" y="44" text-anchor="middle" font-size="11">Analyzer</text>
<text x="639" y="60" text-anchor="middle" font-size="10">reports (md/json)</text>
<rect x="580" y="140" width="118" height="52" rx="4" fill="#eff" stroke="#000"/>
<text x="639" y="160" text-anchor="middle" font-size="11">ELK stack</text>
<text x="639" y="176" text-anchor="middle" font-size="10">ES+Kibana</text>
<line x1="104" y1="102" x2="138" y2="102" stroke="#000" marker-end="url(#a)"/>
<line x1="250" y1="102" x2="284" y2="102" stroke="#000" marker-end="url(#a)"/>
<line x1="390" y1="95" x2="422" y2="55" stroke="#000" marker-end="url(#a)"/>
<line x1="390" y1="105" x2="422" y2="107" stroke="#000" marker-end="url(#a)"/>
<line x1="390" y1="118" x2="422" y2="165" stroke="#000" marker-end="url(#a)"/>
<line x1="536" y1="40" x2="578" y2="46" stroke="#000" marker-end="url(#a)"/>
<line x1="536" y1="170" x2="578" y2="167" stroke="#000" marker-end="url(#a)"/>
</svg>"""

FIG_FLOW = """
<svg viewBox="0 0 360 250" xmlns="http://www.w3.org/2000/svg" font-family="Times New Roman" font-size="11">
<defs><marker id="b" markerWidth="9" markerHeight="9" refX="7" refY="3" orient="auto">
<path d="M0,0 L7,3 L0,6 Z" fill="#000"/></marker></defs>
<rect x="120" y="8" width="120" height="30" rx="4" fill="#eef" stroke="#000"/>
<text x="180" y="27" text-anchor="middle">Event in</text>
<polygon points="180,52 250,80 180,108 110,80" fill="#ffe" stroke="#000"/>
<text x="180" y="78" text-anchor="middle" font-size="10">signature</text>
<text x="180" y="90" text-anchor="middle" font-size="10">match?</text>
<rect x="270" y="64" width="84" height="32" rx="4" fill="#fee" stroke="#000"/>
<text x="312" y="84" text-anchor="middle" font-size="10">raise alert</text>
<polygon points="180,120 250,148 180,176 110,148" fill="#ffe" stroke="#000"/>
<text x="180" y="146" text-anchor="middle" font-size="10">window</text>
<text x="180" y="158" text-anchor="middle" font-size="10">&ge; thresh?</text>
<rect x="270" y="132" width="84" height="32" rx="4" fill="#fee" stroke="#000"/>
<text x="312" y="152" text-anchor="middle" font-size="10">raise alert</text>
<rect x="120" y="196" width="120" height="30" rx="4" fill="#eef" stroke="#000"/>
<text x="180" y="215" text-anchor="middle" font-size="10">persist + cooldown</text>
<line x1="180" y1="38" x2="180" y2="50" stroke="#000" marker-end="url(#b)"/>
<line x1="250" y1="80" x2="270" y2="80" stroke="#000" marker-end="url(#b)"/>
<text x="258" y="74" font-size="9">yes</text>
<line x1="180" y1="108" x2="180" y2="118" stroke="#000" marker-end="url(#b)"/>
<text x="188" y="116" font-size="9">no</text>
<line x1="250" y1="148" x2="270" y2="148" stroke="#000" marker-end="url(#b)"/>
<text x="258" y="142" font-size="9">yes</text>
<line x1="180" y1="176" x2="180" y2="194" stroke="#000" marker-end="url(#b)"/>
<line x1="312" y1="96" x2="312" y2="130" stroke="#000" marker-end="url(#b)"/>
</svg>"""


FIG_TIMELINE = """
<svg viewBox="0 0 720 96" xmlns="http://www.w3.org/2000/svg" font-family="Times New Roman" font-size="11">
<line x1="20" y1="70" x2="700" y2="70" stroke="#000" stroke-width="1"/>
<polygon points="700,70 692,66 692,74" fill="#000"/>
<text x="360" y="90" text-anchor="middle" font-size="10">time &rarr;</text>
<rect x="30" y="46" width="120" height="20" fill="#eef" stroke="#000"/>
<text x="90" y="60" text-anchor="middle" font-size="10">1. Port scan</text>
<rect x="170" y="46" width="170" height="20" fill="#efe" stroke="#000"/>
<text x="255" y="60" text-anchor="middle" font-size="10">2. Brute-force + defaults</text>
<rect x="360" y="46" width="150" height="20" fill="#fee" stroke="#000"/>
<text x="435" y="60" text-anchor="middle" font-size="10">3. HTTP DoS flood</text>
<rect x="530" y="46" width="160" height="20" fill="#ffe" stroke="#000"/>
<text x="610" y="60" text-anchor="middle" font-size="10">4. Exploit probes</text>
<text x="90" y="30" text-anchor="middle" font-size="9">T1046</text>
<text x="255" y="30" text-anchor="middle" font-size="9">T1110 / T1078</text>
<text x="435" y="30" text-anchor="middle" font-size="9">T1498</text>
<text x="610" y="30" text-anchor="middle" font-size="9">T1595 / T1059</text>
<line x1="90" y1="34" x2="90" y2="44" stroke="#888"/>
<line x1="255" y1="34" x2="255" y2="44" stroke="#888"/>
<line x1="435" y1="34" x2="435" y2="44" stroke="#888"/>
<line x1="610" y1="34" x2="610" y2="44" stroke="#888"/>
</svg>"""


def table(headers, rows, caption="", fullwidth=False):
    h = "".join(f"<th>{c}</th>" for c in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    cap = f"<caption>{caption}</caption>" if caption else ""
    t = f"<table><thead><tr>{h}</tr></thead><tbody>{body}</tbody>{cap}</table>"
    return f'<div class="fw">{t}</div>' if fullwidth else t


def build() -> None:
    contrib = table(
        ["#", "Capability", "What it delivers"],
        [["1", "Deployment", "One-command Docker + pure-Python standalone mode"],
         ["2", "Detection coverage", "6 attack categories, each unit-tested"],
         ["3", "Evaluation", "Quantitative precision / recall / F1 on a labelled set"],
         ["4", "Detection engine", "Hybrid signature + rate-based anomaly"],
         ["5", "Threat taxonomy", "MITRE ATT&amp;CK mapping on every alert"],
         ["6", "Quality", "39 automated tests + CI on 3 Python versions"],
         ["7", "Safe tooling", "Bounded, safety-gated attack simulators"],
         ["8", "Security", "Documented threat model + enforced controls"]],
        "TABLE I. Platform capabilities at a glance.")

    related = table(
        ["Ref", "Yr", "Approach", "Result", "Limitation"],
        [["[10]", "2021", "ML attack classification (Bot-IoT)", "RF best (binary), KNN (multi)", "No real-time/streaming eval"],
         ["[11]", "2021", "Threat hunting with Elastic stack", "ELK cost-effective for hunting", "Needs human input + controls"],
         ["[12]", "2021", "Honeynet + flow classification", "Botnet detection via flows", "Limited algorithm comparison"],
         ["[13]", "2020", "IoT + Docker (Cowrie) honeypots", "Creds match Mirai; EU-sourced", "Not all IoT attacks covered"],
         ["[14]", "2019", "Malicious-event detection, ELK+CTI", "Detects+ranks most threats", "False positives; manual cleanup"]],
        "TABLE II. Comparative summary of related studies.", fullwidth=True)

    schema = table(
        ["Field", "Type", "Example", "Purpose"],
        [["timestamp", "date", "2024-01-01T00:00:03Z", "temporal correlation"],
         ["honeypot", "keyword", "telnet / http", "sensor of origin"],
         ["event_type", "keyword", "login_attempt", "observation class"],
         ["source_ip", "ip", "203.0.113.10", "attacker attribution"],
         ["dest_port", "int", "2323", "targeted service"],
         ["username / password", "keyword", "root / xc3511", "credential intel"],
         ["http_path", "text", "/boaform/…", "web-probe analysis"],
         ["command", "text", "wget http://…", "post-auth behaviour"],
         ["success", "bool", "true", "auth outcome"]],
        "TABLE III. Core honeypot event schema (subset).")

    params = table(
        ["Parameter", "Default", "Meaning"],
        [["brute_force_threshold", "5", "failed logins to alert"],
         ["brute_force_window", "60 s", "brute-force window"],
         ["dos_threshold", "50", "requests to alert"],
         ["dos_window", "10 s", "DoS window"],
         ["port_scan_threshold", "8", "distinct ports to alert"],
         ["port_scan_window", "30 s", "scan window"],
         ["alert_cooldown", "30 s", "duplicate suppression"]],
        "TABLE IV. Configurable detection thresholds.")

    rules = table(
        ["Rule", "Type", "Category", "MITRE", "Trigger"],
        [["IOT-DEFAULT-CREDS", "sig", "default-credentials", "T1078.001", "Known IoT default credential"],
         ["TELNET-BRUTE-FORCE", "anom", "brute-force", "T1110.001", "&ge;5 failed logins / 60 s"],
         ["HTTP-DOS-FLOOD", "anom", "denial-of-service", "T1498", "&ge;50 requests / 10 s"],
         ["PORT-SCAN", "anom", "reconnaissance", "T1046", "&ge;8 ports / 30 s"],
         ["SUSPICIOUS-HTTP-PATH", "sig", "active-scanning", "T1595.002", "IoT exploit URL"],
         ["CMD-INJECTION", "sig", "command-injection", "T1059", "Shell payload"]],
        "TABLE V. Detection rules mapped to MITRE ATT&amp;CK.", fullwidth=True)

    controls = table(
        ["Control", "Where", "Purpose"],
        [["Private-target enforcement", "attacks/safety.py", "Sims cannot hit the internet"],
         ["Request/duration caps", "attacks/dos.py", "Bounds the flood simulator"],
         ["Loopback binds by default", "config.py", "Not WAN-exposed unless opted in"],
         ["Non-root container", "Dockerfile", "Least privilege"],
         ["Bounded input buffers", "honeypots", "Prevents memory exhaustion"],
         ["SQL identifier allow-list", "database.py", "Internal query builder safe"],
         ["Network isolation", "docker-compose", "Contains the honeynet segment"]],
        "TABLE VI. Enforced security controls.")

    evalt = table(
        ["Category", "TP", "FP", "FN", "P", "R", "F1"],
        [["default-credentials", "1", "0", "0", "1.00", "1.00", "1.00"],
         ["brute-force", "1", "0", "0", "1.00", "1.00", "1.00"],
         ["denial-of-service", "1", "0", "0", "1.00", "1.00", "1.00"],
         ["active-scanning", "1", "0", "0", "1.00", "1.00", "1.00"],
         ["command-injection", "1", "0", "0", "1.00", "1.00", "1.00"],
         ["<b>Micro-average</b>", "5", "0", "0", "<b>1.00</b>", "<b>1.00</b>", "<b>1.00</b>"]],
        "TABLE VII. Detection performance on the labelled set (2 benign sources, 0 FP).")

    creds = table(
        ["username:password", "Attempts"],
        [["root:xc3511", "high"], ["admin:admin", "high"], ["root:root", "high"],
         ["root:vizxv", "med"], ["support:support", "med"], ["guest:guest", "med"]],
        "TABLE VIII. Sample captured credential intelligence (demo run).")

    refs = [
        "J. Lasquety-Reyes, &ldquo;Global: Smart home&mdash;number of users 2018&ndash;2027,&rdquo; Statista.",
        "&ldquo;What is a smart home and what are the benefits?,&rdquo; Constellation.com.",
        "&ldquo;Smart home: Threats and countermeasures,&rdquo; Rambus, 2017.",
        "&ldquo;A Study of Smart Home Environment and its Security Threats,&rdquo; ResearchGate.",
        "&ldquo;Smart home: Threats and countermeasures,&rdquo; Rambus, 2017.",
        "K. Subramanian and W. Meng, &ldquo;Threat Hunting Using Elastic Stack: An Evaluation,&rdquo; IEEE SOLI, 2021.",
        "H. Qu, D. Qu and J. Tong, &ldquo;Virtual environment for smart home,&rdquo; IEEE CYBER, 2015.",
        "&ldquo;What is an intrusion detection system?,&rdquo; DNSstuff, 2019.",
        "E. Hasson and L. Cheng, &ldquo;Honeypot,&rdquo; Imperva Learning Center.",
        "A. Churcher et al., &ldquo;An experimental analysis of attack classification using ML in IoT networks,&rdquo; Sensors, 21(2):446, 2021.",
        "K. Subramanian and W. Meng, &ldquo;Threat Hunting Using Elastic Stack,&rdquo; IEEE SOLI, 2021.",
        "Banerjee et al., &ldquo;Network traffic analysis based IoT botnet detection using honeynet data,&rdquo; 2021.",
        "S. Bistarelli, E. Bosimini and F. Santini, &ldquo;A Report on the Security of Home Connections with IoT and Docker Honeypots,&rdquo; CEUR-WS Vol-2597.",
        "M. Harikanth and P. Rajarajeswari, &ldquo;Malicious event detection using ELK stack through CTI,&rdquo; IJITEE, 8(7):882&ndash;886, 2019.",
        "MITRE ATT&amp;CK&reg; Enterprise Matrix, The MITRE Corporation.",
        "J. Gamblin, &ldquo;Mirai BotNet source code,&rdquo; GitHub, 2016.",
        "Elastic B.V., &ldquo;Elastic Stack documentation,&rdquo; 2024.",
        "OISF, &ldquo;Suricata User Guide,&rdquo; 2024.",
    ]
    refs_html = "".join(f"<p>[{i}] {r}</p>" for i, r in enumerate(refs, 1))

    listing_engine = (
        "def process(event):\n"
        "    # signature rules (O(1) regex / set lookups)\n"
        "    if (event.user, event.pw) in MIRAI_DEFAULTS:\n"
        "        emit('IOT-DEFAULT-CREDS', T1078_001)\n"
        "    if INJECT_RE.search(event.path or event.cmd):\n"
        "        emit('CMD-INJECTION', T1059)\n"
        "    # anomaly rules (per-source sliding window)\n"
        "    w = failed_logins[event.src]; w.append(now)\n"
        "    trim(w, now, BF_WINDOW)\n"
        "    if len(w) >= BF_THRESHOLD:\n"
        "        emit('TELNET-BRUTE-FORCE', T1110_001)\n"
        "    # per-(src,rule) cooldown suppresses duplicate alerts")

    listing_safety = (
        "def assert_safe_target(host):\n"
        "    for addr in resolve(host):\n"
        "        ip = ip_address(addr)\n"
        "        if not (ip.is_loopback or ip.is_private):\n"
        "            raise SafetyError('non-lab target refused')")

    listing_alert = (
        '{ "rule_id": "TELNET-BRUTE-FORCE",\n'
        '  "category": "brute-force", "severity": "high",\n'
        '  "source_ip": "203.0.113.10", "event_count": 10,\n'
        '  "mitre_technique": "T1110.001",\n'
        '  "mitre_name": "Password Guessing",\n'
        '  "first_seen": "2024-01-01T00:00:20Z" }')

    services = table(
        ["Service", "Port (localhost)", "Role"],
        [["sensors", "2323, 8080", "honeypots + detection engine"],
         ["elasticsearch", "9200", "storage &amp; search"],
         ["logstash", "&mdash;", "ingest pipeline"],
         ["kibana", "5601", "dashboards"]],
        "TABLE IX. Docker Compose services on the isolated bridge network.")

    phases = table(
        ["Phase", "Simulated action", "Rule(s) exercised"],
        [["1", "Port scan", "PORT-SCAN"],
         ["2", "Telnet brute-force + defaults", "TELNET-BRUTE-FORCE, IOT-DEFAULT-CREDS"],
         ["3", "HTTP request flood", "HTTP-DOS-FLOOD"],
         ["4", "Web-exploitation probes", "SUSPICIOUS-HTTP-PATH, CMD-INJECTION"]],
        "TABLE X. Attack phases in the end-to-end demonstration.")

    cli = table(
        ["Command", "Purpose"],
        [["honeynet serve", "run honeypots + detection pipeline"],
         ["honeynet demo", "self-contained end-to-end demonstration"],
         ["honeynet attack &lt;kind&gt;", "run a lab attack simulation"],
         ["honeynet analyze --out r.md", "generate a threat-analysis report"]],
        "TABLE XI. Command-line interface (Appendix B).")

    listing_report = (
        "## Alerts by category\n"
        "| Category            | Count |\n"
        "| brute-force         |   1   |\n"
        "| default-credentials |   1   |\n"
        "| denial-of-service   |   1   |\n"
        "## MITRE ATT&CK techniques observed\n"
        "| T1110.001 | Password Guessing        | 1 |\n"
        "| T1498     | Network Denial of Service | 1 |")

    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>SmartHoneyNet — IEEE Report</title><style>{CSS}</style></head>
<body>
<div class="title-block">
  <h1>Hunt, Detect and Analyse Attacks on a Smart-Home Network using
      Honeypots, an IDS and the ELK Stack</h1>
  <div class="subtitle">A reproducible platform for smart-home network security · University of Jeddah (CCSE)</div>
  <div class="authors">Aleen Saleh Aljohani<br>
    <span class="email">aleensaljohani@gmail.com</span></div>
  <div class="affil">Cybersecurity Department, College of Computer Science and Engineering (CCSE),
    University of Jeddah, Jeddah, Saudi Arabia</div>
</div>

<div class="body">
<p class="abstract"><b>Abstract&mdash;</b>Smart homes are projected to reach roughly 312 million
households by 2027, expanding a poorly-defended Internet-of-Things (IoT) attack surface that botnets
such as Mirai exploit through default credentials and exposed telnet/HTTP interfaces. This paper
presents SmartHoneyNet, a reproducible, tested and quantitatively evaluated platform that combines
honeypots, an intrusion-detection system (IDS) and the ELK stack to hunt, detect and analyse these
attacks on a single host. Two low-interaction honeypots emulate a Mirai-style
telnet IoT hub and a smart-home device web panel; a hybrid signature-plus-anomaly detection engine
classifies six attack categories and maps every alert to MITRE ATT&amp;CK; a pipeline persists all
data to both an embedded SQLite database and to Elasticsearch for Kibana visualisation. The platform
runs on a single host, ships with a 39-test automated suite and enforced security controls, and on a
controlled labelled evaluation set the engine achieves 100% precision and recall with zero false
positives on benign traffic. We detail the architecture, the detection logic, both experiments, the
security and ethics controls, and the remaining limitations of a software-only honeynet.</p>

<p class="keywords"><b>Index Terms&mdash;</b>Honeypot, IoT security, Intrusion Detection, ELK Stack,
Mirai, MITRE ATT&amp;CK, Smart Home, Threat Hunting, Reproducible Research.</p>

<h2>I. Introduction</h2>
<p>Interconnected &ldquo;smart&rdquo; devices&mdash;thermostats, cameras, locks, plugs and hubs&mdash;
have woven themselves into the modern home. Each device is a small networked computer, and collectively
they form a network whose weakest member sets the security of the whole. The defensive problem is
asymmetric: a homeowner has neither the tooling nor the expertise of an enterprise security operations
centre, yet faces the same internet-wide automated adversaries that target large organisations.</p>
<p>The word &ldquo;Hunt&rdquo; captures the intended posture: not merely to block attacks reactively,
but to attract, observe and understand them. A honeypot deliberately exposes an attractive,
instrumented target; whatever an attacker does to it is malicious by definition and therefore worth
studying. Pairing honeypots with an IDS and a log-analytics stack turns those observations into
detections and, ultimately, into actionable intelligence.</p>
<p>This work delivers a smart-home security platform that others can run, inspect, test and measure,
turning the honeypot&ndash;IDS&ndash;ELK approach into a reproducible and quantitatively evaluated
system.</p>
<h3>A. Problem statement</h3>
<p>Smart-home networks are attacked continuously by automated botnets and scanners, yet homeowners
lack visibility into these attacks and researchers lack reproducible, measurable platforms for
studying them in a specifically smart-home context.</p>
<h3>B. Aim and objectives</h3>
<p><b>Aim.</b> To build a reproducible platform that hunts, detects and analyses attacks against a
smart-home network, and to evaluate its detection effectiveness. <b>Objectives:</b> (1) emulate
vulnerable devices with safe honeypots; (2) implement a real-time hybrid IDS; (3) integrate an ELK
pipeline and an offline database; (4) measure detection performance quantitatively; and (5) enforce
responsible-use controls in code rather than in prose.</p>
<h3>C. Contributions</h3>
<p>The platform's headline capabilities are summarised in Table I: a hybrid detection engine, an
explicit ATT&amp;CK taxonomy, a reproducible and automatically-tested implementation, and a published
quantitative evaluation.</p>
{contrib}

<h2>II. Background</h2>
<h3>A. Smart-home networks and their risks</h3>
<p>A smart home links appliances and sensors to a hub/router, controlled through a web or mobile
interface. Representative risks include data and identity theft from unprotected devices,
eavesdropping on device traffic, and (distributed) denial-of-service amplified by the sheer number of
weakly-protected IoT devices available for recruitment into botnets.</p>
<h3>B. Honeypots</h3>
<p>A honeypot is an intentionally exposed, instrumented system whose only purpose is to be attacked so
defenders can study the attacker. <i>Low-interaction</i> honeypots (used here) emulate just enough of
a service to capture intent while never executing attacker input&mdash;a deliberate safety property.
<i>High-interaction</i> honeypots expose real systems and yield richer data at much higher operational
risk.</p>
<h3>C. Intrusion Detection Systems</h3>
<p>Signature-based detection matches known-bad patterns: precise for known threats but blind to novel
ones. Anomaly-based detection models normal behaviour and flags deviations: able to catch new attacks
at the cost of more false positives. Because neither alone is sufficient for the smart-home threat
mix, SmartHoneyNet deliberately combines the two.</p>
<h3>D. The ELK stack and IoT botnets</h3>
<p>Elasticsearch stores and indexes events for fast search; Logstash ingests, parses and enriches
incoming data; Kibana visualises it as dashboards. Mirai and its descendants scan the internet for
open telnet (TCP&nbsp;23) and try a small list of factory-default credentials such as
<code>root:xc3511</code> and <code>admin:admin</code>. This single behaviour accounts for a large
share of real IoT compromise, which is why an accurate telnet honeypot and a default-credential
signature sit at the centre of this design.</p>

<h2>III. Related Work</h2>
<p>Five prior studies frame this project. Study [10] compares machine-learning classifiers on the
Bot-IoT dataset, finding Random Forest best for binary and K-Nearest-Neighbours best for multi-class
classification, but does not consider real-time streaming. Study [11] evaluates the Elastic stack for
threat hunting and finds it cost-effective, while noting the continuing need for human input. Study
[12] uses honeynet-derived network flows to detect IoT botnets. Study [13] deploys Cowrie honeypots
behind Docker and reports that captured credentials match the Mirai list, with most attacks sourced
from Europe. Study [14] combines the ELK environment with threat intelligence to detect and rank
malicious events, at the cost of false positives and manual cleanup.</p>
{related}
<p><b>Difference from existing work.</b> Like [13] we feed honeypots into ELK and like [11] we use ELK
for hunting, but SmartHoneyNet is distinguished by a hybrid detection engine, an explicit MITRE
ATT&amp;CK classification of every alert, a fully reproducible and automatically-tested implementation,
and a quantitative evaluation with published precision/recall&mdash;directly addressing the
&ldquo;qualitative only&rdquo; and &ldquo;not reproducible&rdquo; gaps common to the surveyed work.</p>

<h2>IV. Threat Model</h2>
<p><b>Assets.</b> Device credentials; camera and sensor feeds; device compute and bandwidth; and the
LAN foothold itself. <b>Adversaries.</b> Automated IoT botnets (Mirai-class), opportunistic
internet-wide scanners probing known IoT CVEs, and manual attackers. <b>Trust boundary.</b> The
honeynet lives on an isolated segment that is untrusted inbound and, crucially, has no egress to the
internet or to production/personal devices; ELK management interfaces bind to localhost. Each attacker
goal is expressed directly as a MITRE ATT&amp;CK technique paired with the rule that detects it
(Table&nbsp;V). The platform also reasons about the risks it introduces&mdash;a honeypot used as a
pivot, or attack tooling misused&mdash;and mitigates them with the controls in Table&nbsp;VI.</p>

<h2>V. Methodology</h2>
<p>The platform follows a three-stage flow, expressed as software. First,
<i>attack generation</i>: adversary behaviour is produced by real attackers in a live deployment or by
the built-in, safety-gated simulators in the lab. Second, <i>detection and collection</i>: honeypots
capture every interaction as a structured event that the pipeline persists and runs through the IDS,
producing alerts enriched with an ATT&amp;CK technique and a severity. Third, <i>transformation and
analysis</i>: events and alerts are written to SQLite and, in the full deployment, shipped through
Logstash into Elasticsearch and visualised in Kibana, while an analyzer produces threat reports.</p>

<h2>VI. System Design</h2>
<h3>A. Architecture</h3>
<p>The platform is a pipeline of composable components (Fig.&nbsp;1) that replace a traditional
multi-VM lab with software: the attack simulators generate adversary traffic; the telnet and HTTP
honeypots act as the sensors; and the detection engine&mdash;with an equivalent Suricata rule
file&mdash;plus the ELK services perform detection and analysis.</p>
<figure>{FIG_ARCH}<figcaption class="figcap">Fig. 1. SmartHoneyNet architecture: sensors feed one
pipeline that persists to SQLite, runs the IDS, and exports to the ELK stack and analyzer.</figcaption></figure>
<h3>B. Data model and storage</h3>
<p>Two records flow through the system&mdash;an <code>Event</code> (an observation) and an
<code>Alert</code> (a detection). They serialise identically to a SQLite row and to the JSON that
Elasticsearch indexes, so the offline and ELK paths remain consistent. Table&nbsp;III lists the core
event fields; <code>source_ip</code> is typed as an IP and a companion geo-point supports map
visualisations. SQLite is the local system of record; Elasticsearch provides the same at scale.</p>
{schema}
<h3>C. Detection engine</h3>
<p>The engine is stream-oriented: each event is processed once. Signature rules perform O(1) set and
regular-expression lookups; anomaly rules maintain a per-source sliding window of recent activity and
fire when a rate threshold is exceeded (Fig.&nbsp;2). A per-(source,&nbsp;rule) cooldown collapses a
sustained campaign into a single actionable alert instead of thousands of duplicates. Thresholds are
configurable (Table&nbsp;IV) and the full rule set with ATT&amp;CK mappings is given in Table&nbsp;V.</p>
<figure style="max-width:60%">{FIG_FLOW}<figcaption class="figcap">Fig. 2. Per-event detection flow:
signatures first, then rate-based windows, then persistence with cooldown.</figcaption></figure>
{params}
{rules}
<pre>{listing_engine}</pre>
<div class="figcap" style="text-align:left">Listing 1. Detection engine (simplified).</div>

<h2>VII. Implementation</h2>
<p>The core is implemented in Python using only the standard library (PyYAML optional), which makes it
portable, auditable and trivial to test. The <b>telnet honeypot</b> is a threaded server presenting a
BusyBox banner and login prompts; it records each credential pair, &ldquo;accepts&rdquo; known-weak
credentials to lure the attacker into a fake shell, and logs typed commands&mdash;while never executing
anything and bounding attempts, commands and session time. The <b>HTTP honeypot</b> emulates a
&ldquo;SmartHome Hub 2.4&rdquo; admin panel; it records method, path, user-agent and POSTed credentials,
caps request-body size, and returns only static HTML. The <b>pipeline</b> persists to SQLite, appends
JSON lines for Logstash, runs the engine, and dispatches alerts. The <b>attack simulators</b>&mdash;
port scan, brute-force and a bounded HTTP flood&mdash;are each gated by the safety module (Listing&nbsp;2),
a safe re-implementation of the original's unbounded loop. Deployment is a single
<code>docker compose up -d --build</code>, which starts the honeypots plus Elasticsearch, Logstash and
Kibana on an isolated bridge network; a saved-objects file provisions the dashboards, and a Suricata
rule set mirrors the engine for network-layer detection.</p>
<pre>{listing_safety}</pre>
<div class="figcap" style="text-align:left">Listing 2. Ethics enforced in code: the safety guard.</div>
<p>A representative alert produced by the engine is shown in Listing&nbsp;3; the same object is stored
in SQLite and indexed in Elasticsearch.</p>
<pre>{listing_alert}</pre>
<div class="figcap" style="text-align:left">Listing 3. Example enriched alert (JSON).</div>
<h3>D. Deployment and operations</h3>
<p>A single <code>docker compose up -d --build</code> brings up four services on a dedicated bridge
network (Table&nbsp;IX). The honeypots write JSON lines into a shared volume that Logstash tails and
indexes into Elasticsearch, and the operator imports the saved-objects file to obtain the Kibana
&ldquo;Threat Overview&rdquo; dashboard (alerts by category and ATT&amp;CK technique, top source
addresses, top credential pairs, and events over time). For a hardware or VM IDS, the accompanying
Suricata rule set reproduces the same logic at the packet layer, and its <code>eve.json</code> can be
forwarded into the same pipeline to unify host-honeypot and network alerts. An operations runbook
documents health checks, alert triage, log rotation and threshold tuning.</p>
{services}

<h2>VIII. Security and Ethics Controls</h2>
<p>Because the project ships attack tooling, ethics are enforced <i>in code</i>, not merely documented.
The simulators call the guard in Listing&nbsp;2, which refuses any target that does not resolve
entirely to loopback or private space; the flood simulator additionally enforces hard caps on request
count and duration. Honeypots are low-interaction with bounded buffers and session timeouts; containers
run non-root on an isolated network; and an internal query builder validates identifiers against an
allow-list. Table&nbsp;VI summarises the controls and where each is enforced.</p>
{controls}

<h2>IX. Experiments and Evaluation</h2>
<h3>A. Experiment A&mdash;end-to-end demonstration</h3>
<p>The <code>demo</code> command starts both honeypots on ephemeral ports and launches, in sequence, a
port scan, a telnet brute-force (wrong guesses plus IoT defaults), an HTTP flood and a set of
web-exploitation probes against them. A representative run captured approximately 196 events and raised
alerts in all five exercised categories, reproducing&mdash;and extending from two to six attack
types&mdash;end to end, as a single reproducible command.
The four attack phases and the rules each exercises are listed in Table&nbsp;X and sketched on the
timeline in Fig.&nbsp;3. Aggregating the captured credentials (Table&nbsp;VIII) directly yields the
blocklist of passwords a homeowner must never use.</p>
{phases}
<figure>{FIG_TIMELINE}<figcaption class="figcap">Fig. 3. Demonstration timeline: reconnaissance,
credential attacks, denial-of-service and exploitation probes, each detected in real time.</figcaption></figure>
{creds}
<h3>B. Experiment B&mdash;quantitative detection evaluation</h3>
<p>To measure detection quality we built a labelled event stream of 94 events: 20 benign, human-paced
web requests, one benign strong login, and four attack campaigns from distinct source addresses with
known ground-truth categories. Metrics are computed at source-campaign granularity, which matches how
the rate rules are designed to fire (once per campaign, not once per packet). As shown in
Table&nbsp;VII, the engine detected every campaign in its correct category and raised no alerts on
benign traffic. The result is asserted by a regression test so that a future change which breaks
detection fails CI.</p>
{evalt}
<h3>C. Automated test suite</h3>
<p>The suite comprises 39 pytest tests covering the database, every detection rule with explicit
synthetic timelines, live honeypot interaction, the safety guardrails, the pipeline, the analyzer, the
command-line interface and a full in-process integration run; line coverage is approximately 84%.
Continuous integration runs the suite plus the demo on Python 3.9, 3.11 and 3.12.</p>

<h2>X. Results and Discussion</h2>
<p>The experiments confirm the central hypothesis&mdash;that honeypots, an IDS and ELK form an
effective, low-cost smart-home detection stack&mdash;and strengthen it with measurement. Three findings
stand out. First, <i>default credentials remain the highest-signal indicator</i>: a single login with a
Mirai default pair is immediately and unambiguously malicious, corroborating [13]. Second,
<i>hybrid detection is complementary, not redundant</i>: signatures caught the known (default
credentials, exploit URLs, injection payloads) with high precision, while rate-based anomaly rules
caught behaviour (brute-force, DoS, scanning) that has no fixed signature. Third, <i>the credential
intelligence has direct defensive value</i>, turning attack data into concrete hardening advice.</p>

<h2>XI. Limitations and Future Work</h2>
<p><b>Limitations.</b> The honeypots emulate telnet/HTTP device interfaces; they do not reproduce full
device firmware or non-IP radios such as Zigbee, Z-Wave or BLE. The perfect scores in Section&nbsp;IX
are on a clean, labelled set; production traffic&mdash;content-delivery networks, health-checkers,
NAT'd users&mdash;would produce false positives and demands threshold tuning, which the framework
supports but whose numbers must then be re-measured. Rate rules require a warm-up window and can miss
&ldquo;low-and-slow&rdquo; attacks tuned below the thresholds. These are the honest boundaries within
which the reported results hold.</p>
<p><b>Future work.</b> Promising directions include Cowrie/Dionaea integration for higher-interaction
SSH/telnet and malware capture; an MQTT honeypot (TCP&nbsp;1883) for the dominant smart-home broker; a
a virtual IoT-device environment with realistic device fingerprints; an ML-based anomaly
detector following [10], evaluated against the same labelled sets; GeoIP and threat-intelligence
enrichment in Logstash to attribute and map campaigns; and automated response that pushes high-severity
source addresses to a firewall blocklist.</p>

<h2>XII. Conclusion</h2>
<p>SmartHoneyNet is a reproducible, tested and measured platform for smart-home network security.
It builds on a proven core idea&mdash;honeypots to attract, an IDS to detect, and
ELK to analyse&mdash;and adds a hybrid detection engine covering six attack classes, a MITRE ATT&amp;CK
classification of every alert, a real database and dashboards, a 39-test automated suite with CI,
enforced security-and-ethics controls, and a quantitative evaluation demonstrating 100% precision and
recall with zero false positives on a controlled labelled set. As smart-home adoption races toward
hundreds of millions of households, tools that let defenders hunt the attackers targeting them&mdash;
safely, reproducibly and measurably&mdash;are exactly what the field needs.</p>

<h2>Appendix A: Reproducibility</h2>
<p>All figures are reproducible from the repository. Experiment A: <code>python3 -m honeynet demo</code>.
Experiment B: <code>python3 scripts/evaluate.py</code>. Test suite: <code>make test</code>. Full stack:
<code>docker compose up -d --build</code>, then import the Kibana saved objects.</p>

<h2>Appendix B: Command-line interface</h2>
<p>The platform is driven by a single <code>honeynet</code> command with four sub-commands
(Table&nbsp;XI), so an operator can run the sensors, generate traffic, and produce reports without
touching the code.</p>
{cli}

<h2>Appendix C: Sample analyzer output</h2>
<p>Listing&nbsp;4 shows an excerpt of the Markdown report emitted by <code>honeynet analyze</code>,
which mirrors the aggregations rendered interactively in Kibana.</p>
<pre>{listing_report}</pre>
<div class="figcap" style="text-align:left">Listing 4. Excerpt of a generated threat-analysis report.</div>

<h2>References</h2>
<div class="refs">{refs_html}</div>
</div>
</body></html>"""

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(html, encoding="utf-8")
    print(f"Wrote {OUT} ({OUT.stat().st_size} bytes)")


if __name__ == "__main__":
    build()
