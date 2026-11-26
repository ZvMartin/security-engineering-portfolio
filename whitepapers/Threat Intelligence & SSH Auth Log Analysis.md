# Threat Intelligence & SSH Auth Log Analysis [VM_HOSTNAME]

> **Author:** Zachary V. Martin, CC | **Date:** November 18, 2026 | **Companion Document:** Zero-Trust Cloud Hardening and Post-Quantum SSH Implementation | **Host Analyzed:** [VM_HOSTNAME] (Debian 12, GCP)

> **Sanitization Note:** Public host IPv4 addresses, VPN overlay endpoints, and local system identifiers have been replaced with RFC 5737 TEST-NET documentation ranges and generic placeholders to preserve operational security (OPSEC). External threat telemetry, attacker source IPs, ASNs, and timestamps remain unedited to preserve forensic and threat-intelligence integrity.

## Section 1: Executive Overview

Analysis of `/var/log/auth.log` telemetry captured across two distinct operational windows—August 2–7, 2026, immediately following port relocation from 22 to 8022, and November 17–18, 2026, prior to GCP VPC edge lockdown—demonstrates the inherent limitations of security-through-obscurity. Moving standard SSH administration off default port 22 initially yielded a temporary drop in noise, but once internet-wide automated scanners indexed non-standard port 8022, threat activity rapidly ramped up. The collected log data reveals a progression from automated banner grabbing and cross-protocol exploitation attempts to legacy cryptographic downgrade sweeps and sophisticated, low-and-slow credential stuffing orchestrated across distributed subnets to systematically evade single-IP Fail2Ban thresholds.

## Section 2: Observed Attack Vectors & Reconnaissance Patterns

* **Banner Grabbing & Mass Port Discovery (`[preauth]` Resets & Closes):** Automated scanners routinely swept port 8022 and immediately terminated TCP sessions after reading the OpenSSH banner (`SSH-2.0-OpenSSH_9.2p1`) to fingerprint the operating system and daemon version. Coordinated `/24` scanner blocks (`172.236.228.0/24`, `172.104.11.0/24`, `205.210.31.0/24`, `147.185.132.0/24`, and `162.216.149.0/24`) conducted these reconnaissance probes in rapid three-connection bursts.
* **Cross-Protocol & Directory Traversal Probes (`kex_exchange_identification` Errors):**
  * **HTTP & TLS Probing:** Unsynchronized bots transmitted raw `GET / HTTP/1.1` requests and TLS ClientHello handshakes directly to port 8022, attempting to discover misconfigured web administration interfaces or proxy services.
  * **Path Traversal Attempt:** On August 2, 2026 (20:13:27 UTC), source IP `192.161.49.2` issued `GET /..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1` against port 8022 in an attempt to read system files via web-layer traversal vulnerabilities.
  * **Cloud Scanner Fingerprinting:** Azure-hosted scanning infrastructure (`20.106.168.113`, `40.76.140.215`, `20.168.120.173`, `20.65.219.49`) transmitted `MGLNDD_203.0.113.39_8022` payload strings to confirm active socket bindings on the virtual machine's previously assigned ephemeral IP.
* **SSHv1 & Weak Cryptographic Downgrade Sweeps:** On August 2, 2026 (15:02:18 UTC), source IP `172.105.24.10` executed 10 rapid connection attempts targeting deprecated protocols. The actor attempted force-downgrades to SSH Protocol 1 (`Protocol major versions differ: 2 vs. 1`), legacy key exchange methods (`diffie-hellman-group1-sha1`), and obsolete host key algorithms (`ssh-dss`, `ssh-rsa`, `ecdsa-sha2-nistp384/521`). All attempts were blocked and rejected at `[preauth]`.
* **Distributed Low-and-Slow Credential Stuffing (November 17–18, 2026):** Following rediscovery of port 8022 on `198.51.100.17`, a distributed botnet rotated across subnets `45.156.87.0/24`, `93.152.221.0/24`, `130.12.182.0/24`, and `102.220.161.0/24`. Individual source IPs spaced login attempts 10–40 minutes apart to remain under Fail2Ban's default `maxretry` sliding window. This strategy generated 25 failed authentication attempts across the pool without triggering an automated firewall block. Targeted accounts included high-privilege system users (`root`: 7 attempts, `user`: 4, `admin`: 3, `oracle`: 2) alongside common service and default accounts (`ubuntu`, `pi`, `nagios`, `middleware`, `samba`, `frappe`, `test`, `system`, `usuario`, `camtest`, `dotaserver`, `jacob`, `lunatyk`, `leilin`, `qinshentao`, `lgh`, `pgqcw`).

## Section 3: Top Offending IPs & Coordinated Scanner Subnets

| Rank | Offending IP / Subnet | Observed Activity | Primary Attack Vector & Targeted Accounts |
| :--- | :--- | :--- | :--- |
| 1 | `172.105.24.10` | 10 connections (Aug 2, within 38 seconds) | Aggressive SSHv1 & cryptographic downgrade sweep (`diffie-hellman-group1-sha1`, `ssh-dss`, `ssh-rsa`) + invalid user `pgqcw`. |
| 2 | `45.156.87.0/24` Botnet Cluster (`45.156.87.189`, `.168`, `.65`) | 12 login attempts (Nov 18, 00:15–03:33 UTC) | Paced low-and-slow credential stuffing targeting `root`, `admin`, `oracle`, `user`, `nagios`, `camtest`, `frappe`, `lunatyk`, `leilin`, `qinshentao`. |
| 3 | `93.152.221.0/24` Botnet Cluster (`93.152.221.206`, `.50`, `.210`) | 8 login attempts (Nov 18, 00:06–02:29 UTC) | Paced low-and-slow credential stuffing targeting `root`, `user`, `ubuntu`, `pi`, `samba`, `system`, `usuario`, `jacob`. |
| 4 | `130.12.182.107` | 4 login attempts (Nov 18, 00:37–03:07 UTC) | Slow brute-force probing (~30–60 min intervals) testing `admin`, `user`, `root`, `dotaserver`, `lgh`. |
| 5 | `102.220.161.0/24` Cluster (`102.220.161.85`, `.79`) | 4 login attempts (Nov 18, 00:04–03:33 UTC) | Probed `root` (twice), `middleware`, and `test`. |
| 6 | `172.104.11.51` & `172.104.11.46` | 8 connections (Aug 6–7) | Repeated 3-connection `[preauth]` sweeps plus `GET / HTTP/1.1` banner probes on port 8022. |
| 7 | `35.203.210.0/24` Scanner Range (`.115`, `.123`, `.137`, `.102`, `.30`) | 5 probes (Aug 2–6 & Nov 17) | Continuous internet-wide port/HTTP banner scanning (`GET / HTTP/1.1` and `[preauth]` resets). |
| 8 | `187.191.2.213` (Historical Ban) | Fail2Ban SSH jail ban (Feb 17, 2026) | Triggered automated Fail2Ban `sshd` ban prior to port relocation. |

---

## Section 4: Defensive Conclusions & Architectural Impact

1. **Port Relocation Only Buys Temporary Obscurity:** Shifting SSH management from `TCP/22` to `TCP/8022` provided only a brief reprieve. Once mass internet scanning engines re-indexed the host's open sockets, automated threat traffic resumed. Non-standard port configurations cannot serve as a primary security boundary.
2. **Low-and-Slow Botnets Evade Threshold-Based Bans:** Traditional single-IP rate-limiting tools (such as Fail2Ban) are insufficient against modern distributed botnets. By rotating across multiple source IPs within diverse `/24` subnets and enforcing strict time delays between attempts, attackers successfully conduct credential stuffing without breaching standard threshold triggers.
3. **Overlay Isolation Eliminates the Attack Surface:** Complete mitigation was achieved by transitioning from public port exposure to zero-trust architecture. Restricting `8022/tcp` strictly to the `tailscale0` overlay interface via UFW and disabling the `ssh-8022-allow` ingress rule at the GCP VPC edge completely eliminated unsolicited SSH probe telemetry.

---

## Appendix A: Sanitized `/var/log/auth.log` Evidence Excerpts

### A.1 SSHv1 & Weak Cryptographic Downgrade Sweep (August 2, 2026)

Rapid multi-vector downgrade attempts from `172.105.24.10` testing SSH Protocol 1, weak Diffie-Hellman key exchange, and deprecated host key algorithms—all rejected at `[preauth]`.

```text
2026-08-02T15:02:18.378803+00:00 [HOST] sshd[32639]: error: Protocol major versions differ: 2 vs. 1
2026-08-02T15:02:18.379070+00:00 [HOST] sshd[32639]: banner exchange: Connection from 172.105.24.10 port 55194: could not read protocol version
2026-08-02T15:02:18.446030+00:00 [HOST] sshd[32640]: Unable to negotiate with 172.105.24.10 port 55180: no matching key exchange method found. Their offer: diffie-hellman-group1-sha1 [preauth]
2026-08-02T15:02:18.702350+00:00 [HOST] sshd[32655]: Unable to negotiate with 172.105.24.10 port 55240: no matching host key type found. Their offer: ssh-dss [preauth]
2026-08-02T15:02:18.754126+00:00 [HOST] sshd[32642]: Invalid user pgqcw from 172.105.24.10 port 55204
2026-08-02T15:02:18.953152+00:00 [HOST] sshd[32658]: Unable to negotiate with 172.105.24.10 port 55250: no matching host key type found. Their offer: ssh-rsa [preauth]
```
### A.2 Cross-Protocol HTTP, TLS, Cloud Scanner & Path Traversal Probes (August 2–4, 2026)

Unsynchronized web/TLS scanners, Azure MGLNDD port-binding probes, and a directory traversal probe targeting port 8022/tcp, rejected during SSH banner exchange.

```text
2026-08-02T01:27:28.922969+00:00 [HOST] sshd[21804]: error: kex_exchange_identification: client sent invalid protocol identifier "GET / HTTP/1.1"
2026-08-02T01:27:29.147032+00:00 [HOST] sshd[21804]: banner exchange: Connection from 35.203.210.115 port 64882: invalid format
2026-08-02T05:57:13.761059+00:00 [HOST] sshd[26946]: error: kex_exchange_identification: client sent invalid protocol identifier "\026\003\001\001"
2026-08-02T05:57:13.761394+00:00 [HOST] sshd[26946]: banner exchange: Connection from 45.79.181.179 port 60456: invalid format
2026-08-02T20:12:06.459045+00:00 [HOST] sshd[36044]: error: kex_exchange_identification: client sent invalid protocol identifier "MGLNDD_203.0.113.39_8022"
2026-08-02T20:12:06.459798+00:00 [HOST] sshd[36044]: banner exchange: Connection from 20.106.168.113 port 58766: invalid format
2026-08-02T20:13:27.699998+00:00 [HOST] sshd[36066]: error: kex_exchange_identification: client sent invalid protocol identifier "GET /..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1"
2026-08-02T20:13:27.700443+00:00 [HOST] sshd[36066]: banner exchange: Connection from 192.161.49.2 port 50296: invalid format
```
### A.3 Distributed Low-and-Slow Botnet Credential Stuffing (November 18, 2026)

Paced authentication attempts rotating across 45.156.87.0/24, 93.152.221.0/24, 130.12.182.0/24, and 102.220.161.0/24 to evade single-IP Fail2Ban rate limits.

```text
2026-11-18T00:04:50.139260+00:00 [HOST] sshd[96973]: Disconnected from authenticating user root 102.220.161.85 port 28494 [preauth]
2026-11-18T00:06:21.774538+00:00 [HOST] sshd[97011]: Invalid user usuario from 93.152.221.206 port 46390
2026-11-18T00:15:24.726669+00:00 [HOST] sshd[97220]: Invalid user lunatyk from 45.156.87.65 port 35894
2026-11-18T00:23:58.654558+00:00 [HOST] sshd[97423]: Invalid user middleware from 102.220.161.85 port 63964
2026-11-18T00:27:41.140013+00:00 [HOST] sshd[97514]: Invalid user leilin from 45.156.87.189 port 33004
2026-11-18T00:37:04.850250+00:00 [HOST] sshd[97741]: Invalid user admin from 130.12.182.107 port 24914
2026-11-18T00:45:36.533519+00:00 [HOST] sshd[97949]: Invalid user samba from 93.152.221.206 port 58378
2026-11-18T00:55:11.193343+00:00 [HOST] sshd[98189]: Invalid user dotaserver from 130.12.182.107 port 62480
2026-11-18T02:23:45.309016+00:00 [HOST] sshd[100366]: Invalid user oracle from 45.156.87.189 port 55454
```

