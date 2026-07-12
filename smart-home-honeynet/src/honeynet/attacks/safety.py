"""Safety guardrails for the attack simulators.

Core control: an attack simulator may only target an address that resolves
*entirely* to loopback or RFC-1918/unique-local private space.  Any attempt
to point the tools at a public host raises :class:`SafetyError` before a
single packet is sent.  This is the technical enforcement of the project's
"lab use only" ethics policy.
"""

from __future__ import annotations

import ipaddress
import socket


class SafetyError(RuntimeError):
    """Raised when an attack tool is aimed at a non-lab target."""


def _addresses(host: str) -> list[str]:
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    infos = socket.getaddrinfo(host, None)
    return sorted({info[4][0] for info in infos})


def is_safe_host(host: str) -> bool:
    """Return True only if *every* resolved address is private/loopback."""
    try:
        addrs = _addresses(host)
    except socket.gaierror:
        return False
    if not addrs:
        return False
    for addr in addrs:
        ip = ipaddress.ip_address(addr)
        if not (ip.is_loopback or ip.is_private or ip.is_link_local):
            return False
    return True


def assert_safe_target(host: str) -> None:
    if not is_safe_host(host):
        raise SafetyError(
            f"Refusing to run attack simulation against non-lab target {host!r}. "
            "Simulators may only target loopback or private (RFC-1918) addresses."
        )
