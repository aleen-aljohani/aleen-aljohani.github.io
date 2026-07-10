"""Telnet brute-force / default-credential simulator (lab only)."""

from __future__ import annotations

import socket
from dataclasses import dataclass, field

from ..config import MIRAI_DEFAULT_CREDENTIALS
from .safety import assert_safe_target

DEFAULT_WORDLIST: list[tuple[str, str]] = list(MIRAI_DEFAULT_CREDENTIALS) + [
    ("root", "toor"),
    ("admin", "admin1234"),
    ("root", "letmein"),
]


@dataclass
class BruteForceResult:
    target: str
    port: int
    attempts: int = 0
    succeeded: list[tuple[str, str]] = field(default_factory=list)


def brute_force(
    host: str,
    port: int,
    wordlist: list[tuple[str, str]] | None = None,
    timeout: float = 3.0,
) -> BruteForceResult:
    """Try a credential wordlist against the lab telnet honeypot.

    Returns which credentials were "accepted".  Refuses non-lab targets.
    """
    assert_safe_target(host)
    creds = wordlist if wordlist is not None else DEFAULT_WORDLIST
    result = BruteForceResult(target=host, port=port)
    for username, password in creds:
        result.attempts += 1
        if _try_login(host, port, username, password, timeout):
            result.succeeded.append((username, password))
    return result


def _try_login(host: str, port: int, username: str, password: str, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            _read(sock)                       # banner + login:
            sock.sendall((username + "\r\n").encode())
            _read(sock)                       # Password:
            sock.sendall((password + "\r\n").encode())
            reply = _read(sock)
            return "incorrect" not in reply.lower()
    except OSError:
        return False


def _read(sock: socket.socket) -> str:
    try:
        return sock.recv(2048).decode("ascii", "ignore")
    except OSError:
        return ""
