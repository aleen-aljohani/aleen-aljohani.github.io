# Operations Runbook

Day-to-day operation of a running SmartHoneyNet.

## Start / stop

| Action | Command |
|---|---|
| Start sensors (standalone) | `python3 -m honeynet serve` |
| Start full stack | `docker compose up -d` |
| Stop full stack | `docker compose down` |
| Tail live alerts | `tail -f logs/alerts.jsonl` |
| Tail live events | `tail -f logs/events.jsonl` |

## Health checks

```bash
# sensors reachable?
nc -vz 127.0.0.1 2323
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/

# elasticsearch healthy?
curl -s http://127.0.0.1:9200/_cluster/health | python3 -m json.tool

# event/alert counts in the local DB
python3 - <<'PY'
from honeynet.database import Database
db = Database("honeynet.db")
print("events:", db.count_events(), "alerts:", db.count_alerts())
PY
```

## Responding to an alert

1. **Triage** — read the alert category, `source_ip`, `mitre_technique` and
   `event_count`.
2. **Pivot** — pull that source's full activity:
   ```bash
   sqlite3 honeynet.db \
     "SELECT timestamp,event_type,username,password,http_path,command
      FROM events WHERE source_ip='<IP>' ORDER BY timestamp;"
   ```
   or in Kibana: filter the Threat Overview dashboard by `source_ip`.
3. **Classify** — brute-force + default-creds from one source is a likely
   automated botnet; exploit-path probing suggests a targeted scanner.
4. **Contain** (production honeynet) — block the source at the segment
   firewall; confirm the honeypot did not egress.
5. **Record** — export a report for the incident:
   ```bash
   python3 -m honeynet analyze --db honeynet.db --out reports/incident-$(date +%F).md
   ```

## Routine maintenance

- **Rotate logs** — `logs/*.jsonl` grow unbounded; rotate/compress daily.
- **Back up** the SQLite DB and Elasticsearch snapshots.
- **Review thresholds** — tune `config/detection_rules.yaml` if you see false
  positives/negatives, then restart the sensors.
- **Update the Mirai credential list** as new default-password campaigns
  appear.

## Tuning detection

Edit `config/detection_rules.yaml` (or set `HONEYNET_RULES`). Lower a
`*_threshold` to detect slower attacks (more sensitive, more false positives);
raise `*_window` to catch "low-and-slow" campaigns. Restart `serve` to apply.

## Common issues

| Symptom | Likely cause | Fix |
|---|---|---|
| `OSError: address already in use` | port in use | change `--telnet-port`/`--http-port` |
| No alerts despite traffic | thresholds too high | lower thresholds in rules file |
| Kibana shows no data | template/dataview missing | import ndjson; check Logstash logs |
| `SafetyError` on attack | target isn't private | only lab/loopback targets are allowed |
| Elasticsearch won't start | low memory / vm.max_map_count | raise `vm.max_map_count=262144` |
