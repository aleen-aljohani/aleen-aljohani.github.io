# Contributing

Contributions that extend the honeynet's coverage of smart-home threats are
welcome.

## Development setup

```bash
cd smart-home-honeynet
python3 -m pip install -e ".[dev]"
make test
```

## Guidelines

- **Keep the runtime standard-library-only** where possible. The core must
  run without third-party packages (PyYAML is optional).
- **Every new detection rule needs a test** in `tests/test_detection_engine.py`
  using synthetic events with explicit timestamps.
- **Never weaken the safety guardrails.** Any new attack tooling must call
  `assert_safe_target()` and be covered by a "refuses public target" test.
- **New event fields** must be added to `models.Event`, the `database` schema
  and the Elasticsearch mapping together.
- Run `make test` and `python -m honeynet demo` before opening a PR.

## Ideas for future work

See the "Future Work" section of
[`docs/report/graduation-report.md`](docs/report/graduation-report.md) —
notably a Cowrie/Dionaea integration, an MQTT honeypot for smart-home
brokers, GeoIP enrichment and an ML-based anomaly detector.
