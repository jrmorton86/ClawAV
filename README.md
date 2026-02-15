<div align="center">

# 🛡️ ClawAV

**Tamper-proof security watchdog for AI agents**

[![Build](https://img.shields.io/github/actions/workflow/status/coltz108/ClawAV/ci.yml?branch=main&style=flat-square)](https://github.com/coltz108/ClawAV/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Release](https://img.shields.io/github/v/release/coltz108/ClawAV?style=flat-square)](https://github.com/coltz108/ClawAV/releases)

</div>

---

## Table of Contents

- [What is ClawAV?](#what-is-clawav)
- [Features](#features)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Usage](#usage)
- [Architecture Overview](#architecture-overview)
- [Contributing](#contributing)
- [License](#license)

## What is ClawAV?

Autonomous AI agents operate with real system access — executing commands, editing files, and managing infrastructure. But who watches the watcher? Traditional security tools weren't designed for a world where the *user* is an AI that could, intentionally or through prompt injection, disable its own monitoring.

ClawAV solves this with the **"swallowed key" pattern**: the agent (or its operator) installs ClawAV, but once running, the agent *cannot* modify, disable, or uninstall it. The binary is immutable (`chattr +i`), the service is protected by systemd, and the admin key is hashed and stored outside the agent's reach. Every attempt to tamper is logged and alerted on.

Under the hood, ClawAV provides real-time file integrity monitoring via inotify, behavioral analysis of syscalls through auditd, threat pattern detection across file contents, and 30+ periodic security scanners — all feeding into a hash-chained audit trail that's cryptographically tamper-evident. Think of it as an immune system for machines running AI agents.

## Features

### 🛡️ Real-time File Sentinel
Inotify-based file watcher with configurable paths and policies. Detects creates, modifications, and deletions instantly. Supports **protected** (alert + quarantine + restore from shadow copy) and **watched** (alert + diff) policies. Content scanning via SecureClaw on every change.

### 🔒 Cognitive File Protection
Dedicated protection for AI identity files — `SOUL.md`, `AGENTS.md`, `IDENTITY.md`, `TOOLS.md`, `USER.md`, `HEARTBEAT.md`. SHA-256 baselines are computed at startup; any modification triggers a CRITICAL alert. Memory files like `MEMORY.md` are tracked with diffs.

### 🔍 SecureClaw Pattern Engine
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

## Quick Start

### One-line Install

```bash
curl -sSL https://raw.githubusercontent.com/coltz108/ClawAV/main/scripts/oneshot-install.sh | sudo bash
```

### Build from Source

```bash
git clone https://github.com/coltz108/ClawAV.git
cd ClawAV
cargo build --release

# Install binaries
sudo install -m 755 target/release/clawav /usr/local/bin/clawav
sudo install -m 755 target/release/clawsudo /usr/local/bin/clawsudo

# Make immutable (the "swallowed key")
sudo chattr +i /usr/local/bin/clawav
```

### Initial Setup

```bash
# Create config directory
sudo mkdir -p /etc/clawav

# Copy and edit config
sudo cp config.toml /etc/clawav/config.toml
sudo nano /etc/clawav/config.toml

# Admin key is auto-generated on first run — check journalctl output to capture it
# It is displayed once and stored only as an Argon2 hash

# Set up monitoring integrations (all optional)
sudo scripts/setup-auditd.sh        # Auditd rules for syscall monitoring
sudo scripts/setup-iptables.sh      # Iptables logging for network alerts
sudo scripts/setup-apparmor.sh      # AppArmor confinement profiles
sudo scripts/setup-sudoers-deny.sh  # Block agent from stopping ClawAV via sudo
sudo scripts/setup-slack.sh         # Configure Slack webhook
sudo scripts/setup-falco.sh         # Falco eBPF monitoring (optional)
sudo scripts/setup-samhain.sh       # Samhain file integrity (optional)
sudo scripts/build-preload.sh       # Build LD_PRELOAD guard library
sudo scripts/enable-preload.sh      # Activate LD_PRELOAD guard
```

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
| `scripts/build-preload.sh` | Compile libclawguard.so |
| `scripts/enable-preload.sh` | Activate LD_PRELOAD guard |
| `scripts/sync-secureclaw.sh` | Update SecureClaw pattern databases |
| `scripts/oneshot-install.sh` | Single-command install from GitHub |

## Configuration

ClawAV uses a TOML config file (default: `/etc/clawav/config.toml`). Key sections:

```toml
[general]
watched_users = ["openclaw"]    # Users to monitor (empty = all)
min_alert_level = "info"        # info | warning | critical
log_file = "/var/log/clawav/clawav.log"

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
log_prefix = "CLAWAV_NET"
allowlisted_cidrs = ["192.168.0.0/16", "10.0.0.0/8"]

[sentinel]
enabled = true
quarantine_dir = "/etc/clawav/quarantine"
shadow_dir = "/etc/clawav/sentinel-shadow"
scan_content = true
debounce_ms = 200

[[sentinel.watch_paths]]
path = "/home/openclaw/.openclaw/workspace/SOUL.md"
patterns = ["*"]
policy = "protected"            # protected = restore + alert; watched = diff + alert

[secureclaw]
enabled = true
vendor_dir = "./vendor/secureclaw/secureclaw/skill/configs"

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
clawav

# Run headless (servers, background monitoring)
clawav run --headless

# Self-update to latest release
clawav update

# Check for updates without installing
clawav update --check

# Admin key is auto-generated on first run and printed once — save it!
# It is stored only as an Argon2 hash at /etc/clawav/admin.key.hash

# Use clawsudo instead of sudo for AI agents
clawsudo apt-get update
```

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│                        ClawAV Core                           │
│                                                              │
│  ┌───────────────────┐  ┌──────────┐  ┌──────────┐          │
│  │  Auditd Watcher   │  │ Sentinel │  │ Journald │ Sources  │
│  │ ┌───────────────┐ │  │ (inotify)│  │  Tailer  │          │
│  │ │Behavior Engine│ │  └────┬─────┘  └────┬─────┘          │
│  │ │SecureClaw     │ │       │              │                │
│  │ │Policy Engine  │ │  ┌────┴────┐   ┌────┴────┐           │
│  │ └───────────────┘ │  │ Scanner │   │Firewall │           │
│  └────────┬──────────┘  │  Loop   │   │ Monitor │           │
│           │             └────┬────┘   └────┬────┘           │
│           ▼                  ▼              ▼                │
│  ┌──────────────────────────────────────────────────┐       │
│  │            raw_tx Channel (mpsc, cap=1000)       │       │
│  └──────────────────────┬───────────────────────────┘       │
│                         ▼                                    │
│  ┌──────────────────────────────────────────────────┐       │
│  │             Alert Aggregator                      │       │
│  │       (fuzzy dedup · rate-limit · suppress)       │       │
│  └──────┬────────────┬────────────┬─────────────────┘       │
│         ▼            ▼            ▼                          │
│  ┌──────────┐  ┌──────────┐  ┌───────────┐                  │
│  │  Slack   │  │   TUI    │  │Audit Chain│  Outputs          │
│  │ Notifier │  │Dashboard │  │  (log)    │                  │
│  └──────────┘  └──────────┘  └───────────┘                  │
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌───────────┐                  │
│  │  REST    │  │  Proxy   │  │  Admin    │  Services         │
│  │  API     │  │  (DLP)   │  │  Socket   │                  │
│  └──────────┘  └──────────┘  └───────────┘                  │
└──────────────────────────────────────────────────────────────┘
```

**Data flow:** The auditd watcher parses syscall events and runs them through behavior analysis, SecureClaw pattern matching, and policy evaluation *before* producing alerts. Other sources (sentinel, journald, scanner, firewall) produce alerts directly. All alerts flow through the `raw_tx` channel to the aggregator, which deduplicates and rate-limits before fanning out to Slack, TUI, REST API, and the hash-chained audit log. The admin socket accepts authenticated commands via Unix domain socket.

## Contributing

### Adding a Scanner

Scanners live in `src/scanner.rs`. Add a new function that returns `ScanResult`:

```rust
fn scan_my_check() -> ScanResult {
    // Your check logic
    ScanResult::new("my_check", ScanStatus::Pass, "All good")
}
```

Register it in the `run_all_scans()` function.

### Adding File Watch Rules

Add entries to `sentinel.watch_paths` in config, or extend `PROTECTED_FILES`/`WATCHED_FILES` in `src/cognitive.rs`.

### Adding Pattern Databases

SecureClaw patterns are loaded from JSON files in the vendor directory (`vendor/secureclaw/`). Four databases are supported:
- `injection-patterns.json` — prompt injection patterns by category
- `dangerous-commands.json` — dangerous command patterns with severity and action
- `privacy-rules.json` — PII/credential regex rules
- `supply-chain-ioc.json` — suspicious skill patterns and C2 indicators

Each file contains regex patterns compiled at startup. Drop updated `.json` files into the vendor directory.

### Adding Policy Rules

Policy rules are YAML files in the `policies/` directory. Detection rules use `action`:

```yaml
rules:
  - name: block-curl-to-external
    description: "Block curl to unknown hosts"
    match:
      command: ["curl", "wget"]
      exclude_args: ["api.anthropic.com", "github.com"]
    action: critical
```

Enforcement rules for `clawsudo` use `enforcement`:

```yaml
rules:
  - name: allow-apt
    match:
      command: ["apt", "apt-get"]
    enforcement: allow

  - name: deny-sudo-shell
    match:
      command: ["bash", "sh", "zsh"]
    enforcement: deny
```

## License

MIT — see [LICENSE](LICENSE) for details.
