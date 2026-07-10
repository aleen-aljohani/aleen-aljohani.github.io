"""Ethical, self-contained attack simulators for lab validation only.

Every simulator is gated by :mod:`honeynet.attacks.safety`, which refuses to
target anything other than loopback / RFC-1918 private addresses.  These
tools exist to exercise the detection pipeline against the project's own
honeypots — not to attack third parties.
"""

from .brute_force import brute_force
from .dos import dos_flood
from .port_scan import port_scan
from .safety import SafetyError, assert_safe_target, is_safe_host

__all__ = [
    "brute_force", "dos_flood", "port_scan",
    "SafetyError", "assert_safe_target", "is_safe_host",
]
