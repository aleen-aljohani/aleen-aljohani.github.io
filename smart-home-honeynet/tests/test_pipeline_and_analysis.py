"""Pipeline integration + analyzer/report tests."""

from honeynet.analysis import Analyzer, render_json, render_markdown
from honeynet.models import Event, EventType


def test_pipeline_persists_events_and_alerts(pipeline, db):
    ev = Event(source_ip="10.0.0.20", honeypot="telnet",
               event_type=EventType.LOGIN_ATTEMPT,
               username="root", password="xc3511", success=True)
    alerts = pipeline.handle(ev)
    assert db.count_events() == 1
    assert db.count_alerts() == len(alerts) >= 1
    assert any(a.rule_id == "IOT-DEFAULT-CREDS" for a in db.get_alerts())


def test_pipeline_jsonl_sinks(tmp_path):
    from honeynet.database import Database
    from honeynet.detection.engine import DetectionEngine
    from honeynet.pipeline import Pipeline

    ev_path = tmp_path / "events.jsonl"
    al_path = tmp_path / "alerts.jsonl"
    db = Database(":memory:")
    pipe = Pipeline(db, DetectionEngine(), events_jsonl=str(ev_path), alerts_jsonl=str(al_path))
    pipe.handle(Event(source_ip="10.0.0.21", honeypot="telnet",
                      event_type=EventType.LOGIN_ATTEMPT,
                      username="admin", password="admin"))
    db.close()
    assert ev_path.exists() and ev_path.read_text().strip()
    assert al_path.exists() and al_path.read_text().strip()


def test_analyzer_summary(db):
    for i in range(6):
        db.insert_event(Event(source_ip="10.0.0.30", honeypot="telnet",
                              event_type=EventType.LOGIN_ATTEMPT,
                              username="root", password="xc3511", dest_port=2323))
    db.insert_event(Event(source_ip="10.0.0.31", honeypot="http",
                          event_type=EventType.HTTP_REQUEST, http_path="/boaform/"))
    summary = Analyzer(db).summarize()
    assert summary.total_events == 7
    assert summary.unique_sources == 2
    assert ("root:xc3511", 6) in summary.top_credentials
    assert any(port == 2323 for port, _ in summary.targeted_ports)


def test_report_rendering(db):
    db.insert_event(Event(source_ip="10.0.0.40", honeypot="http",
                          event_type=EventType.HTTP_REQUEST, http_path="/"))
    summary = Analyzer(db).summarize()
    md = render_markdown(summary)
    assert "# SmartHoneyNet" in md
    assert "MITRE ATT&CK" in md
    js = render_json(summary)
    assert '"total_events": 1' in js
