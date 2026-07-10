# Threat Model

## 1. System under study

A residential **smart-home network**: a hub/router and a set of IoT devices
(cameras, thermostats, sensors, plugs) reachable over the LAN and often
exposed to the internet through port-forwarding or UPnP. These devices are
characterised by weak/default credentials, unpatched firmware, and exposed
telnet/HTTP management interfaces.

## 2. Assets

| Asset | Why an attacker wants it |
|---|---|
| Device credentials | Pivot, persistence, recruit into a botnet |
| Camera/sensor feeds | Privacy invasion, surveillance, extortion |
| Compute/bandwidth | DDoS-for-hire, crypto-mining, proxying |
| LAN foothold | Lateral movement to PCs/phones and data theft |

## 3. Adversaries

- **Automated IoT botnets** (Mirai and variants) — mass telnet scanning with
  default-credential lists; the dominant real-world threat.
- **Opportunistic scanners** — internet-wide HTTP probing for known IoT CVEs
  (D-Link HNAP, GPON, Netgear `setup.cgi`, boaform, …).
- **Manual attackers** — targeted brute-force and exploitation.

## 4. Attacker goals mapped to MITRE ATT&CK (and our detections)

| Tactic | Technique | Attacker action | Detection |
|---|---|---|---|
| Reconnaissance | T1595.002 Active Scanning | Probe IoT exploit URLs | `SUSPICIOUS-HTTP-PATH` |
| Discovery | T1046 Network Service Discovery | Port scan the host | `PORT-SCAN` |
| Credential Access | T1110.001 Password Guessing | Telnet brute force | `SSH-TELNET-BRUTE-FORCE` |
| Credential Access | T1078.001 Default Accounts | Mirai default creds | `IOT-DEFAULT-CREDS` |
| Execution | T1059 Command/Scripting | `;wget|busybox` payloads | `CMD-INJECTION` |
| Impact | T1498 Network DoS | HTTP request flood | `HTTP-DOS-FLOOD` |

## 5. Trust boundaries

```
 Internet  ──►  [ Firewall / segment boundary ]  ──►  Honeynet VLAN
                                                       ├─ telnet honeypot
                                                       ├─ http honeypot
                                                       └─ ELK (localhost only)
```

- The honeynet segment is **untrusted inbound** and must have **no egress**
  to the internet or to production/personal devices.
- ELK management interfaces bind to `127.0.0.1` and require auth before any
  wider exposure.

## 6. Risks introduced by the honeynet itself, and mitigations

| Risk | Mitigation |
|---|---|
| Honeypot is used as a pivot | Low-interaction only; no code execution; no egress |
| Attack tooling misused against third parties | `assert_safe_target()` hard-blocks non-private targets |
| Resource exhaustion by a hostile client | Bounded buffers, session timeouts, DoS-sim hard caps |
| Sensitive data capture (IPs, creds) | Access-controlled storage; data-handling notes in SECURITY.md |
| Container escape | Non-root container, isolated bridge network |

## 7. Out of scope

Physical attacks, RF/Zigbee/Z-Wave radio attacks, firmware supply-chain
compromise, and attacks on the cloud back-ends of commercial devices. These
are candidates for future work (see the graduation report).
