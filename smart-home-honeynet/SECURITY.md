# Security Policy & Responsible-Use Statement

SmartHoneyNet is an **offensive-adjacent research tool**: it deliberately
attracts attackers (honeypots) and includes attack simulators. It must be
operated responsibly.

## Responsible use

- **Lab-only attack tooling.** The simulators in `src/honeynet/attacks/` call
  `assert_safe_target()` before sending a single packet. That function
  resolves the target and raises `SafetyError` unless **every** resolved
  address is loopback or RFC-1918/unique-local private space. Pointing the
  tools at a public host is refused by design.
- **Low-interaction honeypots.** The telnet and HTTP honeypots return only
  canned responses. They never execute attacker-supplied commands, spawn a
  shell, write attacker files to disk, or transfer downloaded payloads.
- **Authorised targets only.** Only deploy against infrastructure you own or
  are explicitly authorised to test.

## Deployment safety controls

| Control | Where | Purpose |
|---|---|---|
| Private-target enforcement | `attacks/safety.py` | Attack sims cannot hit the internet |
| Request/duration hard caps | `attacks/dos.py` (`MAX_REQUESTS`, `MAX_DURATION`) | Bounds the flood simulator |
| Loopback binds by default | `config.py`, `docker-compose.yml` | Honeypots not exposed to WAN unless you opt in |
| Non-root container | `Dockerfile` (`USER honeynet`) | Least privilege |
| Bounded input buffers | `http_honeypot.py` (`MAX_BODY`), `telnet_honeypot.py` (`MAX_*`) | Prevents memory exhaustion from a hostile client |
| Session timeouts | honeypots (`SOCKET_TIMEOUT`) | Reclaims idle/malicious sockets |
| SQL identifier allow-listing | `database.py` (`top()`) | Internal query builder cannot be injected |
| Network isolation | `docker-compose.yml` (dedicated bridge) | Contains the honeynet segment |

## Hardening checklist before a live deployment

1. Run the honeypots on an **isolated VLAN / segment** with no route to
   production or personal devices.
2. Terminate captured traffic there; do **not** allow honeypot egress to the
   internet (block outbound at the firewall).
3. Enable Elasticsearch/Kibana authentication (`xpack.security.enabled=true`)
   and TLS before exposing beyond localhost.
4. Rotate and back up `logs/*.jsonl` and the SQLite database.
5. Review data-protection obligations — captured source IPs and credentials
   may be personal data under local regulation. Restrict access.

## Reporting a vulnerability

This is an academic project. If you find a security issue in the code, please
open a GitHub issue describing the problem and reproduction steps. Do not
include third-party attack data or personal information in reports.
