"""Telnet honeypot emulating a vulnerable smart-home hub / IoT device.

Telnet (TCP/23) is the exact vector abused by the Mirai family against IoT
devices, so it is the most faithful low-interaction sensor for a smart-home
threat model.  The honeypot:

* presents a BusyBox-style banner and ``login:``/``Password:`` prompts;
* records every credential pair as a ``login_attempt`` event;
* "accepts" known-weak / default credentials to lure the attacker into a
  fake shell, where typed commands are captured as ``command`` events;
* never executes anything — responses are canned strings.

It is deliberately low-interaction: no real shell, no filesystem, no code
execution.  That is a safety property, not a limitation.
"""

from __future__ import annotations

import socket
import socketserver
from typing import Optional

from ..config import MIRAI_DEFAULT_CREDENTIALS
from ..models import Event, EventType, new_id
from .base import BaseHoneypot

BANNER = "\r\n(none) login: "
PASSWORD_PROMPT = "Password: "
FAKE_SHELL_PROMPT = "\r\nBusyBox v1.16.1 (2014-03-04) built-in shell (ash)\r\n~ # "
DENIED = "\r\nLogin incorrect\r\n"

# Credentials the honeypot will "accept" so we can observe post-auth behaviour.
ACCEPTED_CREDENTIALS = {(u.lower(), p) for u, p in MIRAI_DEFAULT_CREDENTIALS}

MAX_LOGIN_ATTEMPTS = 6
MAX_COMMANDS = 25
SOCKET_TIMEOUT = 30.0


def _clean(raw: bytes) -> str:
    """Strip telnet IAC negotiation bytes and non-printables."""
    out = bytearray()
    i = 0
    while i < len(raw):
        b = raw[i]
        if b == 0xFF:  # IAC — skip the 2 following negotiation bytes
            i += 3
            continue
        if b in (0x0D, 0x0A):
            i += 1
            continue
        if 0x20 <= b < 0x7F:
            out.append(b)
        i += 1
    return out.decode("ascii", "ignore").strip()


class _Handler(socketserver.BaseRequestHandler):
    honeypot: "TelnetHoneypot"

    def handle(self) -> None:
        self.request.settimeout(SOCKET_TIMEOUT)
        src_ip, src_port = self.client_address[:2]
        session_id = new_id()
        self.honeypot.emit(Event(
            source_ip=src_ip, source_port=src_port, dest_port=self.honeypot.port,
            honeypot="telnet", event_type=EventType.CONNECTION,
            protocol="telnet", session_id=session_id,
        ))
        try:
            authed = self._auth_loop(src_ip, src_port, session_id)
            if authed:
                self._shell_loop(src_ip, src_port, session_id)
        except (socket.timeout, OSError):
            pass
        finally:
            self.honeypot.emit(Event(
                source_ip=src_ip, source_port=src_port, dest_port=self.honeypot.port,
                honeypot="telnet", event_type=EventType.DISCONNECT,
                protocol="telnet", session_id=session_id,
            ))

    def _readline(self) -> Optional[str]:
        data = self.request.recv(1024)
        if not data:
            return None
        return _clean(data)

    def _send(self, text: str) -> None:
        try:
            self.request.sendall(text.encode("ascii", "ignore"))
        except OSError:
            raise

    def _auth_loop(self, src_ip: str, src_port: int, session_id: str) -> bool:
        for _ in range(MAX_LOGIN_ATTEMPTS):
            self._send(BANNER)
            username = self._readline()
            if username is None:
                return False
            self._send(PASSWORD_PROMPT)
            password = self._readline()
            if password is None:
                return False
            accepted = (username.lower(), password) in ACCEPTED_CREDENTIALS
            self.honeypot.emit(Event(
                source_ip=src_ip, source_port=src_port, dest_port=self.honeypot.port,
                honeypot="telnet", event_type=EventType.LOGIN_ATTEMPT,
                protocol="telnet", session_id=session_id,
                username=username, password=password, success=accepted,
            ))
            if accepted:
                self._send(FAKE_SHELL_PROMPT)
                return True
            self._send(DENIED)
        return False

    def _shell_loop(self, src_ip: str, src_port: int, session_id: str) -> None:
        for _ in range(MAX_COMMANDS):
            command = self._readline()
            if command is None:
                return
            if command.lower() in ("exit", "quit", "logout"):
                return
            self.honeypot.emit(Event(
                source_ip=src_ip, source_port=src_port, dest_port=self.honeypot.port,
                honeypot="telnet", event_type=EventType.COMMAND,
                protocol="telnet", session_id=session_id,
                command=command, success=True,
            ))
            self._send(self._fake_response(command) + "\r\n~ # ")

    @staticmethod
    def _fake_response(command: str) -> str:
        c = command.strip()
        if c.startswith("cat "):
            return "\r\ncat: can't open file"
        if c in ("id",):
            return "\r\nuid=0(root) gid=0(root)"
        if c in ("uname", "uname -a"):
            return "\r\nLinux (none) 3.10.0 armv7l GNU/Linux"
        if c.startswith(("wget", "curl", "tftp")):
            return "\r\nConnecting ... download failed"
        return ""


class _ThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class TelnetHoneypot(BaseHoneypot):
    name = "telnet"

    def __init__(self, host: str, port: int, sink) -> None:
        super().__init__(host, port, sink)
        self._server: Optional[_ThreadingTCPServer] = None

    def _serve_forever(self) -> None:
        handler = type("BoundHandler", (_Handler,), {"honeypot": self})
        self._server = _ThreadingTCPServer((self.host, self.port), handler)
        # publish the actually-bound port (supports port=0 in tests)
        self.port = self._server.server_address[1]
        self._started.set()
        self._server.serve_forever(poll_interval=0.2)

    def _shutdown(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
