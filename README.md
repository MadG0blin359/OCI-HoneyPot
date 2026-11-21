# OCI-HoneyPot: Defensive Low-Interaction SSH Honeypot & Threat Intelligence System

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Runtime](https://img.shields.io/badge/Runtime-Node.js%20LTS-brightgreen.svg)](https://nodejs.org/)
[![Cloud Provider](https://img.shields.io/badge/Cloud-Oracle%20Cloud%20Infrastructure%20(OCI)-F80000.svg)](https://www.oracle.com/cloud/)
[![Instance](https://img.shields.io/badge/Architecture-ARM64%20(Ampere%20A1)-blueviolet.svg)](https://www.oracle.com/cloud/compute/arm/)
[![Security](https://img.shields.io/badge/Deception-Low--Interaction%20Tarpit-critical.svg)](#core-defensive--deception-engineering-features)
[![Threat Intel](https://img.shields.io/badge/Format-NDJSON%20%2F%20JSONL-orange.svg)](#threat-intelligence-logging--data-schema)

A high-performance, asynchronous, low-interaction SSH honeypot engineered for deployment on Oracle Cloud Infrastructure (OCI). The system deceives automated brute-force botnets, credential stuffers, and global reconnaissance scanners, passively capturing high-fidelity adversary telemetry while neutralizing denial-of-service attempts via circuit breaking and connection tarpitting.

---

## Table of Contents

- [Overview](#overview)
- [Architecture & System Design](#architecture--system-design)
  - [Cloud Infrastructure on Oracle Cloud Infrastructure (OCI)](#cloud-infrastructure-on-oracle-cloud-infrastructure-oci)
  - [Network Security & Perimeter Ingress Architecture](#network-security--perimeter-ingress-architecture)
  - [System Workflow Diagram](#system-workflow-diagram)
- [Core Defensive & Deception Engineering Features](#core-defensive--deception-engineering-features)
  - [1. Circuit Breaker (DoS Protection & Little's Law)](#1-circuit-breaker-dos-protection--littles-law)
  - [2. IP Jail & Adaptive In-Memory Rate Limiting](#2-ip-jail--adaptive-in-memory-rate-limiting)
  - [3. High-Latency Tarpit Mechanism](#3-high-latency-tarpit-mechanism)
  - [4. Banner Emulation & Anti-Fingerprinting](#4-banner-emulation--anti-fingerprinting)
  - [5. Zero-Risk Low-Interaction Sandbox](#5-zero-risk-low-interaction-sandbox)
  - [6. Connection Lifecycle & Memory Leak Prevention](#6-connection-lifecycle--memory-leak-prevention)
- [Threat Intelligence Logging & Data Schema](#threat-intelligence-logging--data-schema)
  - [Schema Definition](#schema-definition)
  - [Sample Telemetry Record](#sample-telemetry-record)
  - [SIEM & Analytics Ingestion](#siem--analytics-ingestion)
- [Empirical Threat Intelligence Insights & Findings](#empirical-threat-intelligence-insights--findings)
  - [Adversary Case Studies from Field Deployment](#adversary-case-studies-from-field-deployment)
  - [Observed Attack Vectors & Threat Actor Taxonomy](#observed-attack-vectors--threat-actor-taxonomy)
- [Prerequisites & System Requirements](#prerequisites--system-requirements)
- [Installation & Setup](#installation--setup)
- [Configuration & Operational Usage](#configuration--operational-usage)
  - [Configuration Constants](#configuration-constants)
  - [Starting the Honeypot](#starting-the-honeypot)
  - [Production Process Management (PM2)](#production-process-management-pm2)
  - [Port Forwarding (Privileged Port 22 Binding)](#port-forwarding-privileged-port-22-binding)
- [Testing & Validation Protocols](#testing--validation-protocols)
- [Security, Containment & Ethical Disclaimer](#security-containment--ethical-disclaimer)
- [Research Team & Authors](#research-team--authors)
- [License](#license)

---

## Overview

Public-facing cloud infrastructure is subject to constant, automated probing by distributed botnets (such as Mirai, XorDDoS, and Muhstik), mass reconnaissance engines (Shodan, Censys, Masscan, ZMap), and opportunistic credential stuffers. Left unmonitored, these intrusions provide defenders with zero operational visibility into active attack vectors.

**OCI-HoneyPot** was created as an academic research and defensive engineering project at the **National University of Computer & Emerging Sciences (NUCES FAST)**. It acts as an instrumented decoy service on the open internet:
- Emulates a genuine Ubuntu Linux OpenSSH daemon.
- Intercepts authentication attempts across diverse authentication protocols (`password`, `publickey`, `keyboard-interactive`, `none`).
- Extracts attacking IP addresses, usernames, and plaintext passwords into an append-only threat intelligence feed.
- Enforces multi-stage defense-in-depth safeguards (circuit breaking, per-IP rate limiting, and TCP tarpitting) to withstand high-volume volumetric attacks without exhausting host operating system resources.

---

## Architecture & System Design

```
                     Internet Adversaries / Botnets
                 (Masscan, Censys, Hydra, Mirai, etc.)
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │     Oracle Cloud Infrastructure (OCI) VCN        │
          │   Virtual Cloud Network - Stateful Ingress NSG   │
          │   Rule: Allow TCP:2222 from 0.0.0.0/0            │
          │   (Default all-protocol ingress eliminated)      │
          └────────────────────────┬─────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │   Host Firewall (iptables / UFW) on Ubuntu 20.04 │
          │   INPUT -p tcp --dport 2222 -j ACCEPT            │
          └────────────────────────┬─────────────────────────┘
                                   │
                                   ▼
        ┌──────────────────────────────────────────────────────┐
        │        honeypot_v2.js (Node.js Asynchronous I/O)     │
        │                                                      │
        │   ┌──────────────────────────────────────────────┐   │
        │   │ Layer 1: Circuit Breaker                     │   │
        │   │ activeConnections >= 500 ──▶ Drop Socket     │   │
        │   └──────────────────────┬───────────────────────┘   │
        │                          ▼                           │
        │   ┌──────────────────────────────────────────────┐   │
        │   │ Layer 2: IP Jail Rate Limiter                │   │
        │   │ requests > 15/min ─────────▶ Destroy Socket  │   │
        │   └──────────────────────┬───────────────────────┘   │
        │                          ▼                           │
        │   ┌──────────────────────────────────────────────┐   │
        │   │ Layer 3: SSH Banner Deception & Handshake    │   │
        │   │ Ident: OpenSSH_8.2p1 Ubuntu-4ubuntu0.5       │   │
        │   └──────────────────────┬───────────────────────┘   │
        │                          ▼                           │
        │   ┌──────────────────────────────────────────────┐   │
        │   │ Layer 4: Real-Time Telemetry Capture         │   │
        │   │ Append to threat_intel.jsonl (Atomic I/O)    │   │
        │   └──────────────────────┬───────────────────────┘   │
        │                          ▼                           │
        │   ┌──────────────────────────────────────────────┐   │
        │   │ Layer 5: Asynchronous 2000ms Tarpit Delay    │   │
        │   │ setTimeout(2000) ──────────▶ ctx.reject()    │   │
        │   └──────────────────────────────────────────────┘   │
        └──────────────────────────────────────────────────────┘
```

### Cloud Infrastructure on Oracle Cloud Infrastructure (OCI)

The production honeypot was hosted within an Oracle Cloud Infrastructure (OCI) Always-Free tier tenancy with the following configuration:

| Infrastructure Component | Specification / Setting |
| :--- | :--- |
| **Compute Shape** | `VM.Standard.A1.Flex` (ARM64 Ampere Altra Architecture) |
| **OCPUs & Memory** | 2 OCPUs / 12 GB RAM |
| **Operating System** | Ubuntu 20.04 LTS (Canonical Minimal Server) |
| **Public IPv4** | Elastic Public IP assigned via OCI Virtual Cloud Network (VCN) |
| **Internal Management** | Primary administrative SSH isolated from the honeypot port |

### Network Security & Perimeter Ingress Architecture

To adhere to the principle of least privilege and prevent host compromise:
1. **Remediation of Default Security Lists**: The default OCI security rule permitting broad ingress traffic from `0.0.0.0/0` across all ports was removed.
2. **Stateful Ingress Rule**: A dedicated rule was applied permitting only TCP traffic on port `2222` from CIDR `0.0.0.0/0`.
   - `Stateless: False`: Stateful connection tracking delegates bidirectional packet accounting to the OCI hypervisor virtual firewall, automatically permitting ephemeral return packets without opening broad egress rules.
3. **Host Firewall Configuration**: The host-level netfilter table routes incoming packets:
   ```bash
   sudo iptables -I INPUT -p tcp -m tcp --dport 2222 -j ACCEPT
   ```
4. **Administrative SSH Isolation**: Administrative access is restricted to an alternate, hardened interface with key-only authentication, preventing the honeypot port from interacting with real host shell services.

---

## Core Defensive & Deception Engineering Features

The core honeypot engine is implemented in [honeypot_v2.js](honeypot_v2.js) with multi-layered defenses.

### 1. Circuit Breaker (DoS Protection & Little's Law)

An open, public-facing honeypot is vulnerable to distributed denial-of-service (DDoS) flood attacks. Unbounded connection acceptance risks operating system file descriptor exhaustion (`EMFILE: too many open files`).

- **Implementation**: [honeypot_v2.js](honeypot_v2.js#L41-L45) monitors `activeConnections`. If connections reach `MAX_CONCURRENT_CONNECTIONS = 500`, the server invokes `client._sock.destroy()` immediately.
- **System Justification**: By **Little's Law** ($L = \lambda W$):
  $$\text{Concurrent Connections } (L) = \text{Arrival Rate } (\lambda) \times \text{Hold Time } (W)$$
  With a 2-second tarpit hold time ($W = 2\text{s}$), an arrival rate of 500 connections/second yields 1,000 active concurrent sockets. Because Ubuntu's default user file descriptor limit (`ulimit -n`) is **1,024**, setting a threshold of **500** guarantees that the Node.js event loop will never exhaust OS file descriptors or trigger an unhandled process termination.

### 2. IP Jail & Adaptive In-Memory Rate Limiting

To prevent automated scanners (e.g., THC-Hydra, Ncrack) from flooding the log store with gigabytes of repetitive dictionary attacks:

- **Implementation**: [honeypot_v2.js](honeypot_v2.js#L47-L65) maintains an in-memory hash map (`ipTracker`) tracking request volume per source IPv4 address.
- **Window & Threshold**: Rolling window of 60,000 ms (60 seconds) with a ceiling of `MAX_ATTEMPTS_PER_MINUTE = 15`.
- **Immediate Socket Termination**: Sockets exceeding 15 attempts/minute are immediately destroyed at the raw TCP layer (`client._sock.destroy()`), bypassing SSH protocol handshake overhead and conserving CPU cycles.

### 3. High-Latency Tarpit Mechanism

Botnets rely on speed and rapid iteration across target address blocks. When a target delays its response, botnet worker threads are trapped waiting for timeouts.

- **Implementation**: [honeypot_v2.js](honeypot_v2.js#L86-L94) injects an intentional 2,000 ms (2-second) asynchronous delay (`setTimeout`) prior to rejecting the authentication context.
- **Resource Asymmetry**: Node.js handles the delay via non-blocking event-loop timers consuming virtually zero CPU/RAM, while the attacker's client process blocks a synchronous thread/worker for the full duration.
- **Authentication Fallback**: If an attacker attempts methods other than password authentication (e.g., `none` or `publickey`), the server rejects the attempt while signaling `['password', 'publickey']` support, coercing automated clients to downgrade to plaintext password submission.

### 4. Banner Emulation & Anti-Fingerprinting

Network reconnaissance scanners inspect service identification banners to determine exploit viability.

- **Implementation**: [honeypot_v2.js](honeypot_v2.js#L8) configures the SSH daemon identity banner:
  ```javascript
  const FAKE_BANNER = 'OpenSSH_8.2p1 Ubuntu-4ubuntu0.5';
  ```
- **Deception Value**: Matches standard canonical Ubuntu 20.04 LTS installations. When scanned by platforms like Shodan or Censys, the host appears as an authentic enterprise Linux server rather than a known honeypot framework (e.g., Cowrie or Kippo).

### 5. Zero-Risk Low-Interaction Sandbox

Unlike high-interaction honeypots that run sandboxed Docker containers or real shell instances:
- The honeypot **never creates a pseudo-terminal (PTY)**.
- The honeypot **never attaches a shell process or command interpreter**.
- **Every authentication request is rejected** after logging.
- There is mathematically zero surface area for privilege escalation, container escapes, or lateral network movement.

### 6. Connection Lifecycle & Memory Leak Prevention

In high-concurrency Node.js applications, network sockets closed abruptly by remote clients can orphan event listeners or skew counter variables.

- **Implementation**: [honeypot_v2.js](honeypot_v2.js#L96-L108) registers a unified `cleanup()` handler across `client.on('error')`, `client.on('end')`, and `client._sock.on('close')`.
- **Atomic Guard Flag**: Uses a boolean `connectionClosed` guard to ensure `activeConnections` is decremented exactly once per session, preventing counter desynchronization.

---

## Threat Intelligence Logging & Data Schema

Telemetry data is emitted to [threat_intel.jsonl](threat_intel.jsonl) using **Newline Delimited JSON (NDJSON)**. This format supports atomic asynchronous appends (`fs.appendFileSync`) without requiring memory buffers for large JSON structures.

### Schema Definition

| Field | Type | Description | Example |
| :--- | :--- | :--- | :--- |
| `timestamp` | String (ISO 8601) | Exact UTC date and time of the captured event | `"2026-05-10T10:13:40.686Z"` |
| `session_id` | String (Hex, 8 char) | Unique 4-byte random hex token identifying the TCP session | `"a78c25be"` |
| `ip_address` | String (IPv4) | Sanitized attacker IP (IPv6 mapping prefix stripped) | `"59.103.246.18"` |
| `username` | String | Username targeted by the adversary | `"superadmin"` |
| `password` | String | Plaintext password captured (or `"N/A"` for non-password auth) | `"sdgfgdfg"` |
| `auth_method` | String | Authentication method tested (`password`, `publickey`, `none`, `keyboard-interactive`) | `"password"` |

### Sample Telemetry Record

```json
{
  "timestamp": "2026-05-10T10:13:40.686Z",
  "session_id": "a78c25be",
  "ip_address": "59.103.246.18",
  "username": "superadmin",
  "password": "sdgfgdfg",
  "auth_method": "password"
}
```

### SIEM & Analytics Ingestion

The NDJSON log format allows ingestion by security pipelines:

```bash
# Live stream parsing with jq
tail -f threat_intel.jsonl | jq '{time: .timestamp, ip: .ip_address, user: .username, pass: .password}'

# Frequency analysis of top targeted usernames
jq -r '.username' threat_intel.jsonl | sort | uniq -c | sort -nr

# Frequency analysis of unique attacker IPs
jq -r '.ip_address' threat_intel.jsonl | sort | uniq -c | sort -nr
```

The file can be mounted directly into **Elasticsearch / Filebeat**, **Splunk Universal Forwarder**, **Graylog**, or loaded into **Pandas / Jupyter Notebooks** for threat modeling.

---

## Empirical Threat Intelligence Insights & Findings

During live deployment on the public internet (tested at public IP `150.136.37.105`), the honeypot captured real-world adversary behavior. A summary of captured patterns from [threat_intel.jsonl](threat_intel.jsonl) is detailed below.

### Adversary Case Studies from Field Deployment

#### 1. Targeted Administrator Credential Stuffing (`59.103.246.18`)
- **Telemetry Breakdown**: 12 authentication attempts across 2 distinct sessions (`a78c25be` and `d04832f9`).
- **Tactics, Techniques & Procedures (TTPs)**:
  1. Initiates connection with `auth_method: "none"` to test if the host permits unauthenticated access.
  2. Tests `auth_method: "publickey"` to probe for accepted keys.
  3. Escalates to password brute-force targeting `username: "superadmin"`.
  4. Tests `auth_method: "keyboard-interactive"` fallback.
  5. Cycles passwords: `sdgfgdfg`, `ehs`, `sdry`, `e5yeyr`, `sodgi098`, `dfhbvn`.
- **Classification**: Scripted credential-stuffing engine executing structured protocol fallback sequences.

#### 2. Default Factory & IoT Exploit Spraying (`45.148.10.121`)
- **Telemetry Breakdown**: 10 authentication attempts across 5 sessions (`2f58053a`, `fbc974ca`, `4902abf7`, `37b8e4c2`, `c9e55b5d`).
- **Target Credentials Captured**:
  - `admin:admin`
  - `AdminGPON:ALC#FGU`
  - `root:admin`
  - `user:user`
  - `root:root`
- **Threat Intelligence Significance**: The pair `AdminGPON:ALC#FGU` represents a known hardcoded credential exploit targeting **GPON Fiber Optical Network Terminals (ONTs)** and CWMP management interfaces (associated with Mirai-variant botnets and fiber router worm propagators).

#### 3. Automated Mass Reconnaissance & Brute-Force (`128.199.225.7`, `47.76.162.139`)
- Probing default Raspberry Pi and cloud Linux accounts: `pi:raspberry`, `ubuntu:ubuntu123`, `root`, `dbadmin`.
- Probes with empty passwords and rapid disconnects matching stateless scanning engines (Masscan / ZMap).

### Observed Attack Vectors & Threat Actor Taxonomy

```
┌────────────────────────────────────────────────────────────────────────┐
│                      Observed Threat Profiles                          │
├─────────────────────────┬──────────────────────┬───────────────────────┤
│ Threat Category         │ Tools / Signatures   │ Target Profile        │
├─────────────────────────┼──────────────────────┼───────────────────────┤
│ Internet Scanners       │ Masscan, ZMap, Shodan│ Ephemeral TCP probes, │
│                         │ Censys crawlers      │ Banner verification   │
├─────────────────────────┼──────────────────────┼───────────────────────┤
│ Credential Stuffers     │ THC-Hydra, Ncrack,   │ superadmin, admin,    │
│                         │ Custom Python scripts│ Dictionary wordlists  │
├─────────────────────────┼──────────────────────┼───────────────────────┤
│ IoT / Router Botnets    │ Mirai variants,      │ AdminGPON:ALC#FGU,    │
│                         │ Muhstik, XorDDoS     │ pi:raspberry, root    │
└─────────────────────────┴──────────────────────┴───────────────────────┘
```

---

## Prerequisites & System Requirements

- **Operating System**: Linux (Ubuntu 20.04 / 22.04 LTS, Debian 11/12, or AlmaLinux/Rocky tested on x86_64 or ARM64).
- **Node.js**: `v14.0.0` or higher (`v18.x` or `v20.x` LTS recommended).
- **Package Manager**: `npm` (bundled with Node.js).
- **Cryptographic Tools**: `ssh-keygen` (standard OpenSSH utility) for generating RSA host keys.
- **Process Manager**: `pm2` recommended for production background daemonization.

---

## Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/ShawaizShahid/OCI-HoneyPot.git
cd OCI-HoneyPot
```

### 2. Install Dependencies

The project relies on the battle-tested, pure-JavaScript `ssh2` server implementation:

```bash
npm install ssh2
```

### 3. Generate RSA Host Key

The honeypot requires an RSA private key file named `honeypot_rsa` in the project root:

```bash
ssh-keygen -t rsa -b 2048 -f ./honeypot_rsa -N ""
```

Verify that both [honeypot_rsa](honeypot_rsa) and [honeypot_rsa.pub](honeypot_rsa.pub) exist:

```bash
chmod 600 ./honeypot_rsa
```

---

## Configuration & Operational Usage

### Configuration Constants

All parameters can be tuned in [honeypot_v2.js](honeypot_v2.js#L5-L15):

```javascript
// --- Configuration ---
const PORT = 2222;                                    // Bind port
const LOG_FILE = './threat_intel.jsonl';              // Telemetry output path
const FAKE_BANNER = 'OpenSSH_8.2p1 Ubuntu-4ubuntu0.5';// Emulated identity

// --- Defensive Safeguards ---
const MAX_CONCURRENT_CONNECTIONS = 500;               // Circuit breaker cap
const MAX_ATTEMPTS_PER_MINUTE = 15;                   // IP Jail rate limit threshold
```

### Starting the Honeypot

To run directly in development or test mode:

```bash
node honeypot_v2.js
```

**Expected Console Output:**
```
===================================================
🛡️  Defensive SSH Honeypot Active
📡 Port: 2222 | Max Capacity: 500 Connections
🕵️‍♂️ Spoofed Banner: OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
📂 Logging to: ./threat_intel.jsonl
🛑 IP Jail: Ban aggressive bots > 15 attempts/min
===================================================
Waiting for inbound threat traffic...
```

### Production Process Management (PM2)

For 24/7 background operation, auto-restart on system reboots, and crash resilience, use PM2:

```bash
# Install PM2 globally
sudo npm install -g pm2

# Launch honeypot under PM2 management
pm2 start honeypot_v2.js --name "ssh-honeypot"

# Verify execution status
pm2 status

# Save the process list to revive on reboot
pm2 save

# Generate and configure systemd startup script
pm2 startup
```

**Operational Monitoring Commands:**
- **Real-Time Logs**: `pm2 logs ssh-honeypot`
- **Resource Monitor**: `pm2 monit`
- **Graceful Restart**: `pm2 restart ssh-honeypot`
- **Stop**: `pm2 stop ssh-honeypot`

### Port Forwarding (Privileged Port 22 Binding)

To capture attackers probing the standard SSH port (22) without running Node.js as root:
1. Move legitimate host administrative SSH to a non-standard port (e.g., `22022`) in `/etc/ssh/sshd_config` and reload SSH.
2. Route incoming port 22 traffic to the honeypot port 2222 via kernel iptables NAT redirection:
   ```bash
   sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
   ```

---

## Testing & Validation Protocols

### 1. Tarpit & Credential Capture Verification

From an external machine, initiate an SSH connection to the honeypot:

```bash
ssh testuser@<YOUR_SERVER_IP> -p 2222
```

- **Observed Behavior**: A 2-second delay occurs before the password prompt rejects the attempt.
- **Log Verification**:
  ```bash
  tail -n 1 threat_intel.jsonl
  ```
  Confirms capture of `testuser`, IP address, timestamp, and session ID.

### 2. Rate Limiting & IP Jail Validation

Test the anti-flooding mechanism by triggering >15 connection requests within 60 seconds:

```bash
for i in {1..20}; do
  ssh -o ConnectTimeout=1 -p 2222 fakeuser@<YOUR_SERVER_IP>
done
```

- **Observed Behavior**: Upon exceeding 15 attempts, subsequent connections are immediately closed (`Connection closed by remote host`) without entering the SSH authentication handshake.

---

## Security, Containment & Ethical Disclaimer

> [!IMPORTANT]
> **Defensive Security Notice**
> 
> - **Zero Execution Surface**: This honeypot is strictly low-interaction. It does not spawn bash, sh, or any pseudo-terminal. It is incapable of executing remote shell commands or serving files.
> - **Passive Threat Intelligence Gathering**: All data collected consists solely of unauthenticated or rejected connection attempts directed at the honeypot's network interface.
> - **Cloud Provider Compliance**: Operating this honeypot within Oracle Cloud Infrastructure (OCI) complies with standard acceptable use guidelines when configured defensively. It must never be used to initiate attacks, scan external networks, or reflect traffic.
> - **Management Isolation**: Always isolate administrative SSH management from the honeypot listening port.

---

## Research Team & Authors

This project was engineered and documented as an academic research study:

- **Shawaiz Shahid** (Roll No: 23P-0599) — National University of Computer & Emerging Sciences (FAST-NUCES)
- **Waleed Afzal** (Roll No: 23P-0566) — National University of Computer & Emerging Sciences (FAST-NUCES)
- **Institution**: FAST-NUCES Faisalabad-Chiniot Campus
- **Date**: May 2026

---

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for complete terms and copyright details.

```
Copyright (c) 2026 Shawaiz Shahid
```
