"""HTTP honeypot emulating a smart-home device web interface.

Presents a fake "SmartHome Hub" / IP-camera admin panel.  Every request is
recorded as an ``http_request`` event; credential POSTs also populate the
username/password fields.  Responses are static HTML — no server-side logic
is ever executed, and the emulated login always fails.

This sensor feeds the DoS-flood, active-scanning and command-injection
detection rules.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import parse_qs, urlparse

from ..models import Event, EventType, new_id
from .base import BaseHoneypot

_LOGIN_PAGE = (
    "<!doctype html><html><head><title>SmartHome Hub</title></head>"
    "<body><h1>SmartHome Hub 2.4</h1>"
    "<form method='POST' action='/login'>"
    "<input name='username' placeholder='admin'>"
    "<input name='password' type='password'>"
    "<button>Sign in</button></form></body></html>"
)

MAX_BODY = 64 * 1024  # never buffer more than 64 KiB of attacker payload


class _Handler(BaseHTTPRequestHandler):
    honeypot: "HttpHoneypot"
    server_version = "SmartHomeHub/2.4"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # silence default stderr logging
    def log_message(self, fmt: str, *args: object) -> None:  # noqa: A003
        return

    def _record(self, method: str, body: bytes = b"") -> None:
        parsed = urlparse(self.path)
        username = password = None
        if parsed.path == "/login" and body:
            form = parse_qs(body.decode("utf-8", "ignore"))
            username = (form.get("username") or [None])[0]
            password = (form.get("password") or [None])[0]
        self.honeypot.emit(Event(
            source_ip=self.client_address[0],
            source_port=self.client_address[1],
            dest_port=self.honeypot.port,
            honeypot="http",
            event_type=EventType.HTTP_REQUEST,
            protocol="http",
            http_method=method,
            http_path=self.path,
            user_agent=self.headers.get("User-Agent"),
            username=username,
            password=password,
            payload_size=len(body),
            raw={"query": parsed.query},
        ))

    def _respond(self, code: int, body: str, ctype: str = "text/html") -> None:
        payload = body.encode("utf-8")
        try:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Server", self.server_version)
            self.end_headers()
            self.wfile.write(payload)
        except OSError:
            pass

    def do_GET(self) -> None:  # noqa: N802
        self._record("GET")
        path = urlparse(self.path).path
        if path in ("/", "/index.html", "/login"):
            self._respond(200, _LOGIN_PAGE)
        else:
            self._respond(404, "<html><body>404 Not Found</body></html>")

    def do_POST(self) -> None:  # noqa: N802
        length = min(int(self.headers.get("Content-Length", 0) or 0), MAX_BODY)
        body = self.rfile.read(length) if length else b""
        self._record("POST", body)
        # emulated authentication always fails
        self._respond(401, "<html><body>Authentication failed</body></html>")

    def do_HEAD(self) -> None:  # noqa: N802
        self._record("HEAD")
        self._respond(200, "")


class HttpHoneypot(BaseHoneypot):
    name = "http"

    def __init__(self, host: str, port: int, sink) -> None:
        super().__init__(host, port, sink)
        self._server: Optional[ThreadingHTTPServer] = None

    def _serve_forever(self) -> None:
        handler = type("BoundHandler", (_Handler,), {"honeypot": self})
        self._server = ThreadingHTTPServer((self.host, self.port), handler)
        self._server.daemon_threads = True
        self.port = self._server.server_address[1]
        self._started.set()
        self._server.serve_forever(poll_interval=0.2)

    def _shutdown(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
