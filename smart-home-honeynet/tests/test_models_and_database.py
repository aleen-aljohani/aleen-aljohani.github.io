from honeynet.models import Alert, Event, EventType


def test_event_roundtrip_json():
    ev = Event(source_ip="10.0.0.9", honeypot="telnet",
               event_type=EventType.LOGIN_ATTEMPT, username="root",
               password="xc3511", raw={"k": "v"})
    clone = Event.from_dict(ev.to_dict())
    assert clone.source_ip == "10.0.0.9"
    assert clone.username == "root"
    assert clone.raw == {"k": "v"}


def test_database_insert_and_count(db):
    ev = Event(source_ip="10.0.0.1", honeypot="http",
               event_type=EventType.HTTP_REQUEST, http_path="/", success=False)
    db.insert_event(ev)
    assert db.count_events() == 1
    stored = db.get_events()[0]
    assert stored.http_path == "/"
    assert stored.success is False


def test_database_success_boolean_persists(db):
    db.insert_event(Event(source_ip="1.1.1.1", honeypot="telnet",
                          event_type=EventType.LOGIN_ATTEMPT, success=True))
    assert db.get_events()[0].success is True


def test_database_alert_and_category_counts(db):
    for cat in ("brute-force", "brute-force", "denial-of-service"):
        db.insert_alert(Alert(rule_id="R", category=cat, severity="high",
                              source_ip="2.2.2.2", description="x"))
    assert db.count_alerts() == 3
    counts = dict(db.category_counts())
    assert counts["brute-force"] == 2
    assert counts["denial-of-service"] == 1


def test_top_rejects_unknown_column(db):
    import pytest
    with pytest.raises(ValueError):
        db.top("password; DROP TABLE events")


def test_top_aggregation(db):
    for ip in ("9.9.9.9", "9.9.9.9", "8.8.8.8"):
        db.insert_event(Event(source_ip=ip, honeypot="http",
                              event_type=EventType.HTTP_REQUEST))
    top = dict(db.top("source_ip"))
    assert top["9.9.9.9"] == 2
    assert top["8.8.8.8"] == 1
