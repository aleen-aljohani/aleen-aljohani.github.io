"""Live tests: start each honeypot on an ephemeral port and interact with it."""

import socket
import urllib.request

from honeynet.honeypots import HttpHoneypot, TelnetHoneypot
from honeynet.models import EventType


def _telnet_login(host, port, username, password, timeout=3.0):
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.recv(1024)
        s.sendall((username + "\r\n").encode())
        s.recv(1024)
        s.sendall((password + "\r\n").encode())
        return s.recv(1024).decode("ascii", "ignore")


def test_telnet_honeypot_records_login():
    events = []
    hp = TelnetHoneypot("127.0.0.1", 0, events.append)
    hp.start()
    try:
        reply = _telnet_login("127.0.0.1", hp.port, "root", "xc3511")
    finally:
        hp.stop()
    login_events = [e for e in events if e.event_type == EventType.LOGIN_ATTEMPT]
    assert login_events, "no login attempt recorded"
    assert login_events[0].username == "root"
    assert login_events[0].password == "xc3511"
    assert login_events[0].success is True
    assert "BusyBox" in reply or "#" in reply


def test_telnet_honeypot_rejects_bad_credentials():
    events = []
    hp = TelnetHoneypot("127.0.0.1", 0, events.append)
    hp.start()
    try:
        reply = _telnet_login("127.0.0.1", hp.port, "root", "definitely-wrong")
    finally:
        hp.stop()
    login_events = [e for e in events if e.event_type == EventType.LOGIN_ATTEMPT]
    assert login_events[0].success is False
    assert "incorrect" in reply.lower()


def test_http_honeypot_records_request_and_credentials():
    events = []
    hp = HttpHoneypot("127.0.0.1", 0, events.append)
    hp.start()
    try:
        base = f"http://127.0.0.1:{hp.port}"
        urllib.request.urlopen(base + "/", timeout=3).read()
        data = b"username=admin&password=admin"
        req = urllib.request.Request(base + "/login", data=data,
                                     headers={"User-Agent": "pytest"})
        try:
            urllib.request.urlopen(req, timeout=3).read()
        except urllib.error.HTTPError:
            pass  # honeypot intentionally returns 401
    finally:
        hp.stop()
    http_events = [e for e in events if e.event_type == EventType.HTTP_REQUEST]
    assert any(e.http_path == "/" for e in http_events)
    login = [e for e in http_events if e.http_path == "/login"]
    assert login and login[0].username == "admin" and login[0].password == "admin"
