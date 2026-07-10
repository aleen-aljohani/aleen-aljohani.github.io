"""Tests for the attack simulators and their safety guardrails."""

import pytest

from honeynet.attacks import (
    SafetyError,
    assert_safe_target,
    brute_force,
    dos_flood,
    is_safe_host,
    port_scan,
)
from honeynet.honeypots import HttpHoneypot, TelnetHoneypot


def test_is_safe_host_allows_loopback_and_private():
    assert is_safe_host("127.0.0.1")
    assert is_safe_host("10.1.2.3")
    assert is_safe_host("192.168.1.10")
    assert is_safe_host("172.16.5.5")


def test_is_safe_host_blocks_public():
    assert not is_safe_host("8.8.8.8")
    assert not is_safe_host("1.1.1.1")


def test_assert_safe_target_raises_on_public():
    with pytest.raises(SafetyError):
        assert_safe_target("93.184.216.34")


def test_brute_force_refuses_public_target():
    with pytest.raises(SafetyError):
        brute_force("8.8.8.8", 23)


def test_dos_refuses_public_target():
    with pytest.raises(SafetyError):
        dos_flood("http://example.com/")


def test_port_scan_refuses_public_target():
    with pytest.raises(SafetyError):
        port_scan("8.8.8.8")


def test_brute_force_finds_default_credentials():
    events = []
    hp = TelnetHoneypot("127.0.0.1", 0, events.append)
    hp.start()
    try:
        result = brute_force("127.0.0.1", hp.port,
                             wordlist=[("root", "nope"), ("root", "xc3511")])
    finally:
        hp.stop()
    assert result.attempts == 2
    assert ("root", "xc3511") in result.succeeded
    assert ("root", "nope") not in result.succeeded


def test_dos_flood_against_local_honeypot():
    events = []
    hp = HttpHoneypot("127.0.0.1", 0, events.append)
    hp.start()
    try:
        url = f"http://127.0.0.1:{hp.port}/"
        result = dos_flood(url, count=30, concurrency=5, duration=5.0)
    finally:
        hp.stop()
    assert result.sent >= 1
    assert result.sent <= 30


def test_dos_flood_respects_hard_cap():
    events = []
    hp = HttpHoneypot("127.0.0.1", 0, events.append)
    hp.start()
    try:
        url = f"http://127.0.0.1:{hp.port}/"
        # ask for far more than MAX_REQUESTS but a short duration bounds it
        result = dos_flood(url, count=10_000_000, concurrency=4, duration=1.0)
    finally:
        hp.stop()
    from honeynet.attacks.dos import MAX_REQUESTS
    assert result.sent <= MAX_REQUESTS


def test_port_scan_detects_open_port():
    events = []
    hp = HttpHoneypot("127.0.0.1", 0, events.append)
    hp.start()
    try:
        result = port_scan("127.0.0.1", ports=[hp.port, hp.port + 1])
    finally:
        hp.stop()
    assert hp.port in result.open_ports
