"""Mapping of detection categories to MITRE ATT&CK techniques.

Providing an explicit ATT&CK mapping turns raw alerts into analyst-friendly
intelligence and is one of the concrete improvements over the original
project, which classified attacks only as "DoS" or "brute force".
"""

from __future__ import annotations

from typing import NamedTuple


class Technique(NamedTuple):
    technique_id: str
    name: str
    tactic: str


# category -> ATT&CK technique
TECHNIQUES: dict[str, Technique] = {
    "brute-force": Technique("T1110.001", "Brute Force: Password Guessing", "Credential Access"),
    "default-credentials": Technique("T1078.001", "Valid Accounts: Default Accounts", "Credential Access"),
    "denial-of-service": Technique("T1498", "Network Denial of Service", "Impact"),
    "reconnaissance": Technique("T1046", "Network Service Discovery", "Discovery"),
    "active-scanning": Technique("T1595.002", "Active Scanning: Vulnerability Scanning", "Reconnaissance"),
    "command-injection": Technique("T1059", "Command and Scripting Interpreter", "Execution"),
    "exploitation": Technique("T1190", "Exploit Public-Facing Application", "Initial Access"),
    "malware-download": Technique("T1105", "Ingress Tool Transfer", "Command and Control"),
}

UNKNOWN = Technique("T0000", "Uncategorised Activity", "Unknown")


def lookup(category: str) -> Technique:
    return TECHNIQUES.get(category, UNKNOWN)
