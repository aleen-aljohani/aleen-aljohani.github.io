# Deployment Guide

Two deployment modes: **standalone** (Python only, ideal for development and
the graduation demo) and **full stack** (honeypots + ELK via Docker).

## A. Standalone (Python only)

Requirements: Python 3.9+.

```bash
cd smart-home-honeynet
python3 -m pip install -e ".[dev]"

# End-to-end demo (self-contained): honeypots + attacks + report
python3 -m honeynet demo

# Or run the sensors as a long-lived service
python3 -m honeynet serve --telnet-port 2323 --http-port 8080 --db honeynet.db
```

Events stream to `logs/events.jsonl`, alerts to `logs/alerts.jsonl`, and
everything is stored in `honeynet.db`. Generate a report at any time:

```bash
python3 -m honeynet analyze --db honeynet.db --format markdown --out reports/analysis.md
python3 -m honeynet analyze --db honeynet.db --format json   --out reports/analysis.json
```

## B. Full stack with ELK (Docker)

Requirements: Docker + Docker Compose, ~2 GB RAM free for Elasticsearch.

```bash
cd smart-home-honeynet
docker compose up -d --build
```

This starts four services on an isolated bridge network:

| Service | Port (localhost) | Role |
|---|---|---|
| `sensors` | 2323 (telnet), 8080 (http) | honeypots + detection engine |
| `elasticsearch` | 9200 | storage & search |
| `logstash` | — | ingest pipeline (`config/logstash/pipeline`) |
| `kibana` | 5601 | dashboards |

### First-time Kibana setup

1. Open <http://127.0.0.1:5601>.
2. **Stack Management → Saved Objects → Import** and select
   `config/kibana/honeynet-dashboards.ndjson`.
3. Open the **"SmartHoneyNet — Threat Overview"** dashboard.

The honeypots write `logs/events.jsonl` and `logs/alerts.jsonl` into the
shared `honeynet-logs` volume; Logstash tails them and indexes into
`honeynet-events-*` and `honeynet-alerts-*`.

### Optional: install the index template

```bash
curl -X PUT "http://127.0.0.1:9200/_index_template/honeynet" \
     -H 'Content-Type: application/json' \
     -d @config/elasticsearch/honeynet-events-template.json
```

### GeoIP enrichment

The Logstash pipeline includes a `geoip` filter. To enrich external source
IPs, mount a MaxMind GeoLite2 database into the Logstash container and point
the filter at it. Private/lab addresses are tagged `_geoip_lookup_private`
and skipped.

## C. Network-layer IDS (Suricata / Snort)

`config/suricata/smarthome.rules` mirrors the Python engine at the packet
level for a hardware/VM IDS. Load it into Suricata:

```bash
cp config/suricata/smarthome.rules /etc/suricata/rules/
# add to suricata.yaml:  rule-files: [ "smarthome.rules" ]
suricata -T -c /etc/suricata/suricata.yaml   # validate
```

Forward Suricata's `eve.json` into the same Logstash pipeline to unify
host-honeypot and network alerts.

## D. Generating attack traffic (lab only)

```bash
python3 -m honeynet attack port-scan   --host 127.0.0.1
python3 -m honeynet attack brute-force --host 127.0.0.1 --port 2323
python3 -m honeynet attack dos         --url http://127.0.0.1:8080/ --count 200
```

All simulators refuse non-private targets. See [threat-model.md](threat-model.md).

## E. Teardown

```bash
docker compose down          # stop the stack
docker compose down -v       # ... and delete indexed data
make clean                   # remove local db/logs/reports
```
