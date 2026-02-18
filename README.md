<div align="center">

# 🛡️ ClawTower

**OS-level runtime security for AI agents — any agent, any framework**

[![Build](https://img.shields.io/github/actions/workflow/status/ClawTower/ClawTower/ci.yml?branch=main&style=flat-square)](https://github.com/ClawTower/ClawTower/actions)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue?style=flat-square)](LICENSE)
[![Release](https://img.shields.io/github/v/release/ClawTower/ClawTower?style=flat-square)](https://github.com/ClawTower/ClawTower/releases)

</div>

---

Autonomous AI agents operate with real system access — executing commands, editing files, and managing infrastructure. But who watches the watcher? Traditional security tools weren't designed for a world where the *user* is an AI that could, intentionally or through prompt injection, disable its own monitoring.

ClawTower solves this with the **"swallowed key" pattern**: the agent (or its operator) installs ClawTower, but once running, the agent *cannot* modify, disable, or uninstall it. The binary is immutable (`chattr +i`), the service is protected by systemd, and the admin key is hashed and stored outside the agent's reach. Every attempt to tamper is logged and alerted on.

Under the hood, ClawTower provides real-time file integrity monitoring via inotify, behavioral analysis of syscalls through auditd, threat pattern detection across file contents, and 30+ periodic security scanners — all feeding into a hash-chained audit trail that's cryptographically tamper-evident. Think of it as an immune system for machines running AI agents.

Marketplace scanners like VirusTotal are great at catching known malware signatures. ClawTower catches the *unknown* — novel exfiltration, privilege escalation, reverse shells, and tamper attempts — through behavioral analysis and policy enforcement. **They're complementary.** Use both.

## Quick Start

### One-line Install

```bash
curl -sSL https://raw.githubusercontent.com/ClawTower/ClawTower/main/scripts/oneshot-install.sh | sudo bash
```

### Build from Source

```bash
git clone https://github.com/ClawTower/ClawTower.git
cd ClawTower
cargo build --release

# Install binaries
sudo install -m 755 target/release/clawtower /usr/local/bin/clawtower
sudo install -m 755 target/release/clawsudo /usr/local/bin/clawsudo

# Make immutable (the "swallowed key")
sudo chattr +i /usr/local/bin/clawtower
```

### Initial Setup

```bash
# 1. Create config directory and copy config
sudo mkdir -p /etc/clawtower
sudo cp config.toml /etc/clawtower/config.toml

# Customize via drop-in overrides (survives updates)
sudo mkdir -p /etc/clawtower/config.d
sudo nano /etc/clawtower/config.d/my-overrides.toml    # watched_users, slack webhook, etc.

# 2. Run the setup script (installs binary, creates dirs, sets up systemd)
sudo scripts/setup.sh

# 3. Admin key is auto-generated on first run — save it!
#    It is displayed ONCE in journalctl output and stored only as an Argon2 hash
```

> **Note:** Don't edit `config.toml` directly — it gets replaced on updates. Put your customizations in `/etc/clawtower/config.d/*.toml` drop-in files instead.

**Recommended hardening** (run after setup):

```bash
sudo scripts/setup-auditd.sh        # Syscall monitoring — highly recommended
sudo scripts/setup-sudoers-deny.sh  # Block agent from stopping ClawTower
sudo scripts/setup-slack.sh         # Slack alerts
```

**Optional integrations** (add as needed):

```bash
sudo scripts/setup-iptables.sh      # Network alert logging
sudo scripts/setup-apparmor.sh      # AppArmor confinement
sudo scripts/build-preload.sh       # Build LD_PRELOAD guard library
sudo scripts/enable-preload.sh      # Activate LD_PRELOAD guard
sudo scripts/setup-falco.sh         # Falco eBPF monitoring
sudo scripts/setup-samhain.sh       # Samhain file integrity
```

> 📖 **Full installation guide:** See [`docs/INSTALL.md`](docs/INSTALL.md) for prerequisites, hardening details, and recovery procedures.

### Available Scripts

| Script | Purpose |
|--------|---------|
| `scripts/setup.sh` | Full installation (binary, dirs, systemd service) |
| `scripts/install.sh` | Apply tamper-proof hardening (chattr +i, sudoers deny) |
| `scripts/configure.sh` | Interactive config wizard |
| `scripts/uninstall.sh` | Reverse hardening + remove (requires admin key) |
| `scripts/setup-auditd.sh` | Install auditd rules |
| `scripts/setup-audit-rules.sh` | Configure specific audit watch rules |
| `scripts/setup-iptables.sh` | Configure iptables logging |
| `scripts/setup-apparmor.sh` | Load AppArmor profiles |
| `scripts/setup-falco.sh` | Install/configure Falco |
| `scripts/setup-samhain.sh` | Install/configure Samhain |
| `scripts/setup-slack.sh` | Configure Slack webhooks |
| `scripts/setup-sudoers-deny.sh` | Sudoers deny rules for agent |
| `scripts/build-preload.sh` | Compile libclawtower.so |
| `scripts/enable-preload.sh` | Activate LD_PRELOAD guard |
| `scripts/sync-barnacle.sh` | Update BarnacleDefense pattern databases |
| `scripts/oneshot-install.sh` | Single-command install from GitHub |

---

## Who It's For

ClawTower is **agent-agnostic**. It works at the OS level — auditd, AppArmor, syscall interception — so it doesn't need hooks into your agent's code. If it runs on Linux, ClawTower can watch it:

- **[OpenClaw](https://openclaw.ai)** agents and ClawHub skills
- **Claude Code**, **Codex CLI**, **Aider**, **Continue**
- **Devin**, **SWE-agent**, and other autonomous coding agents
- **Custom agents** built on LangChain, CrewAI, AutoGen, or raw API calls
- Any process running under a monitored user account

No SDK integration required. Install ClawTower, point it at the user your agent runs as, and it starts watching.

## How ClawTower Fits

AI agent security isn't one layer — it's a stack. Different tools cover different stages:

| Layer | When | What | Examples |
|-------|------|------|----------|
| **Marketplace scanning** | Pre-install | Static analysis of skill/plugin packages | OpenClaw + VirusTotal, npm audit |
| **Code review** | Pre-execution | LLM-powered behavioral analysis of code | OpenClaw Code Insight, manual review |
| **Runtime monitoring** | Continuous | Watching what agents *actually do* on the machine | **ClawTower** |
| **Network policy** | Continuous | Controlling outbound connections | **ClawTower** netpolicy, firewall rules |

**ClawTower operates at the runtime layer** — the part that catches what static scanning can't:

- A skill passes VirusTotal but uses prompt injection to exfiltrate data at runtime
- An agent's behavior changes after a context window is poisoned
- A legitimate tool (`curl`, `scp`) is used for unauthorized data transfer
- Someone tampers with the agent's identity or configuration files

## Features

### 🛡️ Real-time File Sentinel
Inotify-based file watcher with configurable paths and policies. Detects creates, modifications, and deletions instantly. Supports **protected** (alert + quarantine + restore from shadow copy) and **watched** (alert + diff) policies. Content scanning via BarnacleDefense on every change.

### 🔒 Cognitive File Protection
Dedicated protection for AI identity files — `SOUL.md`, `AGENTS.md`, `IDENTITY.md`, `TOOLS.md`, `USER.md`, `HEARTBEAT.md`. SHA-256 baselines are computed at startup; any modification triggers a CRITICAL alert. Memory files like `MEMORY.md` are tracked with diffs.

### 🔍 BarnacleDefense Pattern Engine
Loads pattern databases for prompt injection, dangerous commands, privacy violations, and supply-chain IOCs. Regex-compiled at startup and applied to file contents in real-time. Pluggable vendor directory for community-maintained rulesets.

### 📊 30+ Security Scanners
Periodic scans covering firewall status (UFW), auditd configuration, SSH hardening, Docker security, kernel parameters, open ports, world-writable files, SUID binaries, cognitive file integrity, crontab auditing, and more. Configurable interval.

### 🔗 Hash-Chained Audit Trail
Every alert is appended to a sequential, SHA-256 hash-chained log. Each entry includes the hash of the previous entry, making retroactive tampering detectable. Chain integrity is verifiable at any time.

### 🖥️ Terminal UI
Full-featured Ratatui dashboard with six tabbed views: Alerts (live feed), Network, Falco, FIM (Samhain), System status, and interactive Config editor. Navigate with keyboard shortcuts; edit config in-place.

### 🔔 Slack Alerts
Real-time notifications to Slack via webhook with severity filtering, failover to a backup webhook, and periodic health heartbeats. Configurable minimum alert level for Slack delivery.

### 🔄 Auto-Updater
Checks GitHub releases every 5 minutes (configurable). Downloads new binaries with **Ed25519 signature verification** against an embedded public key. Performs the `chattr -i` → replace → `chattr +i` → restart dance automatically.

### 🚪 clawsudo
A sudo proxy/gatekeeper binary. Every privileged command the agent runs goes through policy evaluation first. Rules can allow, deny, or alert on specific commands, arguments, and file access patterns. Denied commands return exit code 77.

### 🧬 Behavioral Analysis & Auditd Monitoring
Syscall-level monitoring through auditd with behavioral classification: data exfiltration, privilege escalation, security tampering, reconnaissance, and side-channel attacks. Distinguishes between agent and human actors via auid attribution. Includes LD_PRELOAD guard, build tool suppression, and safe-host allowlisting.

### 🔑 API Key Vault Proxy
Reverse proxy that maps virtual API keys to real ones — the agent never sees actual credentials. Provider-aware header rewriting for Anthropic and OpenAI. Built-in DLP (Data Loss Prevention) scanning blocks SSNs, AWS keys, and redacts credit card numbers from outbound requests.

### 🌐 Network Policy Engine
Allowlist or blocklist mode for outbound connections. Supports wildcard suffix matching (e.g., `*.anthropic.com`). Scans commands for embedded URLs and validates against policy.

### 🔐 Admin Key System
"Swallowed key" authentication: Argon2-hashed admin key generated once and never stored. Required for custom binary updates, uninstall, and admin socket commands. Rate limited (3 failures → 1 hour lockout). Unix domain socket for authenticated runtime commands (status, scan, pause, config-update).

### 📝 Log Tamper Detection
Monitors audit log files for evidence destruction: missing files, inode replacement (distinguishing log rotation), and file truncation. Critical alerts on any suspicious change.

## Configuration

ClawTower uses a TOML config file (default: `/etc/clawtower/config.toml`). Key sections:

```toml
[general]
watched_users = ["1000"]        # Numeric UIDs to monitor (not usernames! find with: id -u openclaw)
min_alert_level = "info"        # info | warning | critical
log_file = "/var/log/clawtower/clawtower.log"

[slack]
webhook_url = "https://hooks.slack.com/services/..."
backup_webhook_url = ""         # Failover webhook
channel = "#security"
min_slack_level = "warning"     # Only send warnings+ to Slack
heartbeat_interval = 3600       # Health ping every hour (0 = off)

[auditd]
enabled = true
log_path = "/var/log/audit/audit.log"

[network]
enabled = true
source = "auto"                 # auto | journald | file
log_prefix = "CLAWTOWER_NET"
allowlisted_cidrs = ["192.168.0.0/16", "10.0.0.0/8"]

[sentinel]
enabled = true
quarantine_dir = "/etc/clawtower/quarantine"
shadow_dir = "/etc/clawtower/sentinel-shadow"
scan_content = true
debounce_ms = 200

[[sentinel.watch_paths]]
path = "/home/openclaw/.openclaw/workspace/SOUL.md"
patterns = ["*"]
policy = "protected"            # protected = restore + alert; watched = diff + alert

[barnacle]
enabled = false
vendor_dir = "./vendor/barnacle/barnacle/skill/configs"

[scans]
interval = 300                  # Seconds between scan sweeps

[auto_update]
enabled = true
interval = 300                  # Check GitHub every 5 minutes

[proxy]
enabled = false
bind = "127.0.0.1"
port = 18790

[api]
enabled = false
bind = "0.0.0.0"
port = 18791

[policy]
enabled = true
dir = "./policies"              # YAML policy rules for clawsudo

[netpolicy]
enabled = false
mode = "blocklist"              # allowlist | blocklist
blocked_hosts = ["evil.com"]

[ssh]
enabled = true                  # Monitor SSH login events via journald
```

> 📖 **Full configuration reference:** See [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) for every field, type, default value, and TOML example.

## Usage

```bash
# Start with Terminal UI (default)
clawtower

# Run headless (servers, background monitoring)
clawtower run --headless

# One-shot security scan and exit
clawtower scan

# Show service status
clawtower status

# Interactive configuration wizard
clawtower configure

# Self-update to latest release
clawtower update

# Check for updates without installing
clawtower update --check

# Verify audit chain integrity
clawtower verify-audit

# Update BarnacleDefense pattern databases
clawtower sync

# Apply tamper-proof hardening
clawtower harden

# Tail service logs
clawtower logs

# Uninstall (requires admin key)
clawtower uninstall

# Admin key is auto-generated on first run and printed once — save it!
# It is stored only as an Argon2 hash at /etc/clawtower/admin.key.hash

# Use clawsudo instead of sudo for AI agents
clawsudo apt-get update
```

## Architecture Overview

```
┌────────────────────────────────────────────────────────────┐
│                      ClawTower Core                        │
│                                                            │
│  ┌───────────────────┐  ┌──────────┐  ┌──────────┐        │
│  │  Auditd Watcher   │  │ Sentinel │  │ Journald │ Sources│
│  │ ┌───────────────┐ │  │ (inotify)│  │  Tailer  │        │
│  │ │Behavior Engine│ │  └────┬─────┘  └────┬─────┘        │
│  │ │BarnacleDefense│ │       │              │              │
│  │ │Policy Engine  │ │  ┌────┴────┐   ┌────┴────┐         │
│  │ └───────────────┘ │  │ Scanner │   │Firewall │         │
│  └────────┬──────────┘  │  Loop   │   │ Monitor │         │
│           │             └────┬────┘   └────┬────┘         │
│           ▼                  ▼              ▼              │
│  ┌──────────────────────────────────────────────────┐     │
│  │            raw_tx Channel (mpsc, cap=1000)       │     │
│  └──────────────────────┬───────────────────────────┘     │
│                         ▼                                  │
│  ┌──────────────────────────────────────────────────┐     │
│  │             Alert Aggregator                      │     │
│  │       (fuzzy dedup · rate-limit · suppress)       │     │
│  └──────┬────────────┬────────────┬─────────────────┘     │
│         ▼            ▼            ▼                        │
│  ┌──────────┐  ┌──────────┐  ┌───────────┐                │
│  │  Slack   │  │   TUI    │  │Audit Chain│  Outputs       │
│  │ Notifier │  │Dashboard │  │  (log)    │                │
│  └──────────┘  └──────────┘  └───────────┘                │
│                                                            │
│  ┌──────────┐  ┌──────────┐  ┌───────────┐                │
│  │  REST    │  │  Proxy   │  │  Admin    │  Services      │
│  │  API     │  │  (DLP)   │  │  Socket   │                │
│  └──────────┘  └──────────┘  └───────────┘                │
└────────────────────────────────────────────────────────────┘
```

**Data flow:** The auditd watcher parses syscall events and runs them through behavior analysis, BarnacleDefense pattern matching, and policy evaluation *before* producing alerts. Other sources (sentinel, journald, scanner, firewall) produce alerts directly. All alerts flow through the `raw_tx` channel to the aggregator, which deduplicates and rate-limits before fanning out to Slack, TUI, REST API, and the hash-chained audit log. The admin socket accepts authenticated commands via Unix domain socket.

## Contributing

Contributions are welcome! Whether it's new detection rules, security scanners, bug fixes, or documentation improvements — we'd love your help.

See **[CONTRIBUTING.md](CONTRIBUTING.md)** for how to get started, including the CLA process, development guidelines, and areas where help is most needed.

## License

AGPL-3.0 — see [LICENSE](LICENSE) for details.

---

> 📚 **[Full Documentation Index →](docs/INDEX.md)**

---

<div align="center">

If ClawTower is useful to you, consider giving it a star — it helps others find the project.

**[Report a Bug](https://github.com/ClawTower/ClawTower/issues)** · **[Request a Feature](https://github.com/ClawTower/ClawTower/issues)** · **[Contributing Guide](CONTRIBUTING.md)**

</div>
