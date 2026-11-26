# Zachary V. Martin, CC — Security & Network Engineering Portfolio

**ISC2 Certified in Cybersecurity (CC) [`#3280732`](https://www.credly.com/users/zvmartin)** | Industrial Infrastructure Protection | Defensive Network Architecture, Zero-Trust Overlay Networking, SIEM/XDR & Systems Administration

**Location:** Leamington, ON | **Contact:** ridge.unity885@eagereverest.com

---

## Overview

This repository houses sanitized technical architecture whitepapers, threat intelligence analyses, and infrastructure configurations built and validated across hybrid cloud and on-premises environments. My engineering focus centers on **zero-trust overlay networking, east-west lateral movement containment, endpoint telemetry (SIEM/XDR/EDR), Linux/Windows log & SQL analysis, and high-throughput segmented LAN topologies**.

---

## Technical Whitepapers & Architecture Case Studies

### 1. [Zero-Trust Cloud Hardening and Post-Quantum SSH Implementation](./pdf/Zero-Trust%20Cloud%20Hardening%20and%20Post-Quantum%20SSH%20Implementation.pdf)
- **Focus:** Cloud Perimeter Elimination, Microsegmentation, Post-Quantum Cryptography
- **Summary:** Re-architected a public-facing Debian 12 Google Cloud VM into a dark endpoint by stripping all public TCP ingress (`22`, `443`, `3389`, `8022`) at the GCP VPC and host UFW layers. Hardened server and client endpoints (OpenSSH 10.4p1 on Windows 11 and Termius mobile SSH) to enforce NIST-standardized ML-KEM (`mlkem768x25519-sha256`) and Streamlined NTRU Prime (`sntrup761x25519-sha512`) hybrid post-quantum key exchanges with `ChaCha20-Poly1305` inside an overlay-restricted WireGuard/Tailscale tunnel, eliminating external Nmap attack surfaces while maintaining >600 Mbps overlay throughput.

### 2. [Threat Intelligence & SSH Auth Log Analysis](./pdf/Threat%20Intelligence%20&%20SSH%20Auth%20Log%20Analysis.pdf)
- **Focus:** Log Forensics, Reconnaissance Profiling, Brute-Force Evasion Analysis
- **Summary:** Forensic analysis of `/var/log/auth.log` telemetry captured before perimeter lockdown. Documented automated banner grabbing, cross-protocol HTTP/TLS probing, directory traversal attempts, SSHv1 cryptographic downgrade sweeps, and distributed low-and-slow botnet credential stuffing across multiple `/24` subnets designed to evade single-IP Fail2Ban thresholds.

### 3. [Cloud SIEM/XDR Architecture: Deploying Wazuh over Unidirectional Zero-Trust Tunnels](./whitepapers/03-wazuh-siem-cloud-deployment-tailscale-isolation.md) *(In Progress)*
- **Focus:** Centralized Telemetry, Cloud SIEM, Lateral Movement Prevention
- **Summary:** Deployed a cloud-hosted Wazuh SIEM/XDR manager ingesting real-time Linux and Windows endpoint/event telemetry across a Tailscale mesh network, paired with SQL querying for log filtering and correlation. Engineered unidirectional ACL grants and node tags so endpoints push logs to the SIEM (`1514/tcp`, `1515/tcp`) while strictly blocking the cloud SIEM from initiating outbound east-west connections back into on-premises hosts.

### 4. [Declarative Zero-Trust Microsegmentation with Tailscale ACLs, Tags, and Grants](./whitepapers/04-tailscale-declarative-acl-microsegmentation.md) *(In Progress)*
- **Focus:** Identity-Based Access Control, Principle of Least Privilege, Subnet Isolation
- **Summary:** Replaced default permissive tailnet policies with a deny-by-default declarative JSON/HuJSON policy architecture. Implemented role-based machine tags (`tag:exit-node`, `tag:siem`, `tag:media-server`, `tag:subnet-router`), disabled client-side `--accept-routes` on cloud nodes, and enforced granular port-level grants.

### 5. [Endpoint Detection (Aurora Lite EDR) & Ephemeral Web-Terminal Telemetry Dashboards](./whitepapers/05-aurora-edr-and-ephemeral-ttyd-telemetry-dashboard.md) *(In Progress)*
- **Focus:** Host-Based Intrusion Detection, Containerized Services, Ephemeral Access Control
- **Summary:** Integrated Aurora Lite EDR for Sigma-rule endpoint detection alongside a containerized Docker stack (Homepage, Jellyfin, Bedrock Server) on Linux. Built an API-driven diagnostic dashboard utilizing `ttyd` to execute live Python tailnet monitors, `btop`, and `htop` over WebSockets—configured to immediately terminate the PTY session and close the browser tab upon script exit to prevent persistent unauthorized shell access.

### 6. [Multi-Subnet 10GbE Network Architecture, SPAN Packet Inspection & Broadcast Storm Containment](./whitepapers/06-multi-subnet-10gbe-homelab-and-broadcast-containment.md) *(In Progress)*
- **Focus:** Layer 2/3 Switching, Fault Isolation, Deep Packet Inspection
- **Summary:** Engineered a 10GbE internal LAN backed by symmetrical 3Gbps FTTH and Wi-Fi 7 (WPA3). Isolated a noisy IoT/security tablet onto a secondary OpenWrt router and separate CIDR subnet with a redundant Tailscale subnet router to eliminate broadcast storms on the primary LAN, utilizing managed switch port mirroring (SPAN) and Wireshark for live traffic validation.

---

## Custom Tooling & Projects

- **[TS-MON v3 (`tailscale-network-monitor`)](https://github.com/ZvMartin/tailscale-network-monitor)** — Real-time Python CLI/TUI tailnet monitor tracking node reachability, latency, DERP vs. direct traffic via `/metrics`, and state transitions, embedded into a `ttyd` + Homepage monitoring stack.

---

## Core Technical Competencies
- **SIEM, Logs, EDR & Forensics:** Wazuh SIEM/XDR, Aurora Lite EDR (Sigma Rules), Linux (`auth.log`, `syslog`/`journald`) & Windows Event Log Analysis, SQL Querying & Log Correlation, Wireshark, `tshark`, `tcpdump`, Managed Switch Port Mirroring (SPAN)
- **Network & Zero-Trust Engineering:** Tailscale (Declarative ACLs, Grants, Tags, Subnet Routers, Exit Nodes), WireGuard, OpenWrt, 10GbE Switching, VLANs/Subnets, UFW, GCP VPC Firewalls
- **Systems & Automation:** Linux (Debian/Ubuntu) & Windows Administration, OpenSSH Post-Quantum Hardening (`mlkem768x25519-sha256` & `sntrup761x25519-sha512`), Secure File Transfer & Sync (SFTP, SCP, WinSCP, Total Commander, Robocopy), Docker & Docker Compose, Python Scripting, `ttyd` Ephemeral Terminals, `ffmpeg` Media Transcoding Automation
---

## Certifications & Technical Training
* **ISC2 Certified in Cybersecurity (CC)** — [Verify via Credly](https://www.credly.com/users/zvmartin) | Member ID `#3280732` *(Active through November 2029)*
* **Google Cybersecurity Professional Certificate** — Coursera *(In Progress — Linux, SQL, Network Security & Risk Management)*
* **Advanced Medical First Responder Level 1 (AMFR I)** — St. John Ambulance *(2026)*
* **Standard First Aid, CPR-BLS (Level C) & AED** — *(Valid through July 2027)*
* **Ontario Security Guard License** — Ministry of the Solicitor General *(Active)*
