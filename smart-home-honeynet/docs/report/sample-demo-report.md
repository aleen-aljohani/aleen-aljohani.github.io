# SmartHoneyNet — Threat Analysis Report

_Generated: 2026-07-10T18:50:35+00:00_

## 1. Executive summary

| Metric | Value |
| --- | --- |
| Total events captured | 196 |
| Total alerts raised | 5 |
| Unique source addresses | 1 |
| Distinct attack categories | 5 |

## 2. Alerts by category

| Category | Count |
| --- | --- |
| brute-force | 1 |
| default-credentials | 1 |
| denial-of-service | 1 |
| command-injection | 1 |
| active-scanning | 1 |

## 3. Alerts by severity

| Severity | Count |
| --- | --- |
| high | 2 |
| critical | 2 |
| medium | 1 |

## 4. MITRE ATT&CK techniques observed

| Technique | Name | Count |
| --- | --- | --- |
| T1110.001 | Brute Force: Password Guessing | 1 |
| T1078.001 | Valid Accounts: Default Accounts | 1 |
| T1498 | Network Denial of Service | 1 |
| T1059 | Command and Scripting Interpreter | 1 |
| T1595.002 | Active Scanning: Vulnerability Scanning | 1 |

## 5. Top source addresses

| Source IP | Events |
| --- | --- |
| 127.0.0.1 | 196 |

## 6. Credential intelligence

### 6.1 Most-tried credential pairs

| username:password | Count |
| --- | --- |
| root:guess0 | 1 |
| root:guess1 | 1 |
| root:guess2 | 1 |
| root:guess3 | 1 |
| root:guess4 | 1 |
| root:guess5 | 1 |
| root:guess6 | 1 |
| root:guess7 | 1 |
| root:xc3511 | 1 |
| root:vizxv | 1 |

### 6.2 Most-tried usernames

| Username | Count |
| --- | --- |
| root | 17 |
| admin | 4 |
| guest | 1 |
| support | 1 |

### 6.3 Most-tried passwords

| Password | Count |
| --- | --- |
| admin | 2 |
| guess0 | 1 |
| guess1 | 1 |
| guess2 | 1 |
| guess3 | 1 |
| guess4 | 1 |
| guess5 | 1 |
| guess6 | 1 |
| guess7 | 1 |
| xc3511 | 1 |

## 7. Targeted ports

| Port | Events |
| --- | --- |
| 39703 | 125 |
| 44143 | 71 |

## 8. Suspicious HTTP paths

| Path | Count |
| --- | --- |
| / | 120 |
| /cgi-bin/mainfunction.cgi?action=login&cmd=;wget | 1 |
| /boaform/admin/formLogin | 1 |
| /HNAP1 | 1 |
| /../../etc/passwd | 1 |
| /setup.cgi?next_file=netgear.cfg | 1 |

## 9. Commands captured in honeypot shells

_No data._

## 10. Activity timeline (hourly)

| Hour (UTC) | Events |
| --- | --- |
| 2026-07-10T18:00 | 196 |
