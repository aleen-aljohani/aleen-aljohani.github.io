"""Smoke tests for the command-line interface."""

from honeynet.cli import main
from honeynet.database import Database
from honeynet.models import Event, EventType


def test_cli_analyze_writes_report(tmp_path, capsys):
    db_path = tmp_path / "cli.db"
    db = Database(str(db_path))
    db.insert_event(Event(source_ip="10.0.0.50", honeypot="http",
                          event_type=EventType.HTTP_REQUEST, http_path="/"))
    db.close()

    out = tmp_path / "report.md"
    rc = main(["analyze", "--db", str(db_path), "--out", str(out)])
    assert rc == 0
    assert out.exists()
    assert "SmartHoneyNet" in out.read_text()


def test_cli_analyze_missing_db_returns_error(tmp_path, capsys):
    rc = main(["analyze", "--db", str(tmp_path / "nope.db")])
    assert rc == 2


def test_cli_attack_rejects_public_target():
    import pytest
    from honeynet.attacks import SafetyError
    with pytest.raises(SafetyError):
        main(["attack", "brute-force", "--host", "8.8.8.8", "--port", "23"])
