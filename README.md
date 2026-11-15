<div align="center">

# VPS CyberSec Orchestrator
### Autonomous Linux VPS Security Auditor, Attack Surface Analyzer & Idempotent Hardening Orchestrator

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](LICENSE)
[![DevSecOps: Blue Team](https://img.shields.io/badge/Discipline-Blue_Team_%2F_DevSecOps-059669?style=for-the-badge)](https://github.com/abrantess/vps-cybersec-orchestrator)
[![Compliance: CIS Benchmark](https://img.shields.io/badge/Compliance-CIS_Linux_v2.0.0-7928CA?style=for-the-badge)](https://www.cisecurity.org/)
[![Safety: Zero--Lockout](https://img.shields.io/badge/Safety-Zero--Lockout_Guard-DC2626?style=for-the-badge)](bin/anti_lockout_guard.sh)
[![Architecture: Hybrid Cognitive](https://img.shields.io/badge/Architecture-Human_%2B_AI_Agent_Ready-0284C7?style=for-the-badge)](schemas/ptt_manifest.schema.json)

<p align="center">
  A production-ready, non-destructive DevSecOps orchestration toolkit designed to conduct automated security assessments, attack surface reduction, and idempotent hardening on Linux VPS environments (Ubuntu, Debian, RHEL, Rocky, Alpine) for Systems Engineers, SREs, and Autonomous AI Agents.
</p>

</div>

---

## 🌟 Core Epistemic Philosophy: Hybrid Determinism

Modern infrastructure security demands bridging **Mechanical Determinism (Old School)** with **Cognitive Agentic Orchestration (New School)**:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        VPS CYBERSEC ORCHESTRATOR ARCHITECTURE                          │
├────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                        │
│   [OLD SCHOOL: DETERMINISTIC BARE-METAL CONTROLS]                                      │
│   ┌────────────────────────────────────────────────────────────────────────────────┐   │
│   │  POSIX / Bash Collector • CIS Sysctl Hardening • UFW / Netfilter Micro-Rules   │   │
│   │  OpenSSH Strict Key-Only Config • Fail2ban Protection • Dead-Man's Switch      │   │
│   └───────────────────────────────────────┬────────────────────────────────────────┘   │
│                                           │                                            │
│                                           ▼                                            │
│   [NEW SCHOOL: STRUCTURED AGENTIC ORCHESTRATION]                                       │
│   ┌────────────────────────────────────────────────────────────────────────────────┐   │
│   │  Phase Tracking Tree (PTT) • Zero-Exploitation Contract • Model Context Protocol│   │
│   │  Machine-Readable JSON Telemetry • Structured CWE / CIS Mappings • Dry-Run Sim │   │
│   └────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                        │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

1. **Mechanical Determinism (Old School):** Idempotent state convergence, kernel memory mitigations (`sysctl`), strict firewall policies (`UFW`/`iptables`), automated key rotation, and cryptographic verification.
2. **Cognitive Orchestration (New School):** Structured state tracking via **Phase Tracking Tree (PTT)** schemas, preventing context loss in autonomous agent workflows, enforcing zero-hallucination evidence validation, and outputting clean JSON/Markdown artifacts.

---

## 📋 The 11-Step DevSecOps Execution Protocol

The engine strictly implements the formalized 11-step defensive protocol:

```mermaid
flowchart TD
    S1["1. Baseline Discovery (Read-Only)"] --> S2["2. Attack Surface & Access Controls"]
    S2 --> S3["3. Containers, Daemons & Secrets"]
    S3 --> S4["4. Hybrid Deterministic Instrumentation"]
    S4 --> S5["5. PTT State Tracking Management"]
    S5 --> S6["6. Zero-Exploitation Operational Boundary"]
    S6 --> S7["7. Anti-Lockout Dead-Man's Switch Protocol"]
    S7 --> S8["8. Risk Prioritization (CIS & CWE)"]
    S8 --> S9["9. Idempotent Hardening & Dry-Run Mode"]
    S9 --> S10["10. Persistence & Integrity Checks"]
    S10 --> S11["11. Controlled Scope Initialization"]
```

| Step | Focus Area | Technical Operation & Objective |
|:---:|---|---|
| **1** | **Baseline Discovery** | Non-destructive extraction of kernel release, architecture, uptime, active systemd services, and sysctl baseline. |
| **2** | **Attack Surface & Access** | Audit of OpenSSH daemon config, PAM policies, listening sockets (`ss -tulnp`), and firewall rules. |
| **3** | **Containers & Secrets** | Detection of Docker/Podman daemon configurations, rootless mode, socket permissions (`/var/run/docker.sock`), and volume mounts. |
| **4** | **Hybrid Instrumentation** | Structured integration with Lynis, OpenSCAP, Nmap, and auditd with evidence triage (Confirmed vs. Heuristic). |
| **5** | **PTT State Tracking** | Maintaining cognitive session state via JSON-Schema (`schemas/ptt_manifest.schema.json`) to prevent context drift. |
| **6** | **Zero-Exploitation** | Strict adherence to read-only non-destructive auditing: no brute-force, no DoS, and zero credential printing. |
| **7** | **Anti-Lockout Protocol** | Arming an automatic dead-man's switch rollback timer before touching any network, firewall, or SSH settings. |
| **8** | **Formal Risk Prioritization** | Mapping findings against CWE (Common Weakness Enumeration) and CIS Linux Benchmark levels. |
| **9** | **Idempotent Hardening** | Re-runnable, state-convergent shell scripts with `--dry-run` simulation flags. |
| **10** | **Persistence Detection** | Inspection of `/etc/ld.so.preload`, crontabs, systemd timers, unlinked open files, and kernel taints. |
| **11** | **Controlled Initialization** | Initial scope bounding and interactive questionnaire to prevent accidental collateral disruption. |

---

## ⚡ Quickstart Guide

### 1. Non-Destructive Read-Only Security Audit
Run the automated collector to analyze the host and generate structured JSON & Markdown reports:

```bash
# Clone the repository
git clone https://github.com/abrantess/vps-cybersec-orchestrator.git
cd vps-cybersec-orchestrator

# Run read-only audit collector
sudo bash bin/vps_audit.sh ./reports
```

*Output:*
- `./reports/vps_audit_<HOSTNAME>_<TIMESTAMP>.json`: Machine-readable telemetry for AI Agents, SIEM, or CI/CD pipelines.
- `./reports/vps_audit_<HOSTNAME>_<TIMESTAMP>.md`: Formatted executive Markdown summary.

---

### 2. Dry-Run Hardening Simulation
Preview all proposed hardening changes (sysctl, sshd, firewall) without applying any mutations to the server:

```bash
sudo bash bin/vps_harden.sh --dry-run
```

---

### 3. Active Idempotent Hardening with Dead-Man's Switch
Apply CIS-compliant system hardening with an automatic 5-minute safety rollback timer:

```bash
sudo bash bin/vps_harden.sh --confirm
```

> 🛡️ **Zero-Lockout Protection:** The hardening engine automatically arms `bin/anti_lockout_guard.sh` for 5 minutes. If network connectivity fails, the server automatically disables the firewall and restores the original SSH configuration. Once you confirm active connectivity, the switch is safely disarmed.

---

## 🔒 Automated Hardening Matrix

| Component | Default Unhardened State | Hardened State Enforced | CIS Linux Benchmark |
|---|---|---|---|
| **SSH Daemon** | Password auth enabled, root password login allowed | `PasswordAuthentication no`, `PermitRootLogin prohibit-password`, `MaxAuthTries 3` | CIS 5.2.10, 5.2.11 |
| **Kernel Sysctl** | ICMP redirects accepted, martians unlogged | `accept_redirects = 0`, `log_martians = 1`, `rp_filter = 1`, `tcp_syncookies = 1` | CIS 3.2.1 - 3.2.8 |
| **Memory ASLR** | Variable randomization level | `kernel.randomize_va_space = 2` (Full ASLR) | CIS 1.6.2 |
| **Host Firewall** | Default allow / unconfigured | `UFW` default deny incoming, rate-limited SSH (22), allowed web ports | CIS 3.5.1 |
| **Docker Daemon** | Live restore disabled | `{"live-restore": true}` in `/etc/docker/daemon.json` | CIS Docker 2.1 |

---

## 🤖 AI Agent & MCP Integration

This repository is natively architected for consumption by autonomous AI agents (Anthropic Claude Code, OpenAI Codex, Google Gemini CLI, OpenCode):

- **PTT State Schema:** `schemas/ptt_manifest.schema.json` defines the contract for multi-turn reasoning trees.
- **Sample Agent Output:** `examples/audit_report_sample.json` provides the target JSON structure for programmatic ingestion.

---

## 🤝 Contributing

Contributions from the global DevSecOps, SRE, and AI engineering community are welcome:
1. Fork the Project (`https://github.com/abrantess/vps-cybersec-orchestrator/fork`).
2. Create your Feature Branch (`git checkout -b feature/NewAuditCheck`).
3. Commit your Changes (`git commit -m 'feat: add eBPF socket monitoring check'`).
4. Push to the Branch (`git push origin feature/NewAuditCheck`).
5. Open a Pull Request.

---

## 📜 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for more information.

<div align="center">
<sub>Authored by <b>Abrantes AI Architect</b> (<a href="https://github.com/abrantess">@abrantess</a>) • Independent AI Systems Architect.</sub>
</div>
