"""TCP connect-scan simulator (lab only)."""

from __future__ import annotations

import socket
from dataclasses import dataclass, field

from .safety import assert_safe_target

# ports typically exposed by IoT / smart-home gear
DEFAULT_PORTS = [21, 22, 23, 80, 443, 554, 1883, 2323, 5000, 8080, 8443, 9000]


@dataclass
class ScanResult:
    target: str
    open_ports: list[int] = field(default_factory=list)
    closed_ports: list[int] = field(default_factory=list)


def port_scan(host: str, ports: list[int] | None = None, timeout: float = 0.5) -> ScanResult:
    """Attempt TCP connections to a set of ports on a lab host."""
    assert_safe_target(host)
    targets = ports if ports is not None else DEFAULT_PORTS
    result = ScanResult(target=host)
    for port in targets:
        if _is_open(host, port, timeout):
            result.open_ports.append(port)
        else:
            result.closed_ports.append(port)
    return result


def _is_open(host: str, port: int, timeout: float) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0
