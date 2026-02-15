# CLAUDE.md — ClawAV LLM Onboarding Guide

> **ClawAV** is a tamper-proof, OS-level security watchdog for AI agents. It monitors the host system for threats, policy violations, and tampering — then alerts via TUI dashboard and Slack. It is designed so that even the AI agent it protects **cannot disable or modify it** (the "swallowed key" pattern).

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [Module Guide](#module-guide)
4. [Key Patterns](#key-patterns)
5. [Configuration](#configuration)
6. [Testing](#testing)
7. [Build & Deploy](#build--deploy)
8. [Common Tasks for LLMs](#common-tasks-for-llms)

---

## Project Overview

### What It Does

ClawAV continuously monitors a Linux host where an AI agent (e.g., OpenClaw) runs. It watches for:

- **Command execution** via auditd log tailing (syscalls, EXECVE records)
- **Behavioral threats** — data exfiltration, privilege escalation, reconnaissance, side-channel attacks, container escapes, persistence mechanisms
- **File integrity** — real-time inotify-based sentinel + periodic cognitive file baselines
- **Firewall state changes** — detects if UFW is disabled or rules modified
- **Network activity** — iptables log parsing via journald or syslog files
- **Log tampering** — detects truncation, deletion, or inode replacement of audit logs
- **Security posture** — 30+ periodic system scans (SUID binaries, kernel modules, password policy, etc.)

### The "Swallowed Key" Pattern

ClawAV's critical files (`/usr/local/bin/clawav`, `/etc/clawav/config.toml`, `/etc/clawav/admin.key.hash`, the service file, and sudoers deny rules) are protected with Linux `chattr +i` (immutable flag). The admin key needed to modify these is generated once, displayed, and never stored — the operator must save it externally. The AI agent has no access to the key and cannot:

- Stop the ClawAV service
- Modify its config
- Remove immutable flags
- Escalate via sudo (blocked by `/etc/sudoers.d/clawav-deny`)

Auditd rules watch for `chattr` invocations targeting ClawAV files and fire Critical alerts.

### Binaries

- **`clawav`** — Main watchdog binary (TUI dashboard, headless daemon, scanner, updater, etc.)
- **`clawsudo`** — Sudo proxy/gatekeeper that evaluates commands against YAML policies before allowing `sudo` execution

---

## Architecture

### Crate Structure

Binary crate only (`src/main.rs`), no `lib.rs`. All modules are declared as `mod` in `main.rs`.

### Event Pipeline

```
Sources (auditd, network, falco, samhain, SSH, firewall, scanner, sentinel, proxy)
    │
    ▼ raw_tx (mpsc::channel<Alert>, cap=1000)
    │
    ▼ Aggregator (dedup + rate limiting)
    │
    ├──▶ alert_tx → TUI (render in dashboard)
    ├──▶ slack_tx → SlackNotifier (webhook)
    ├──▶ api_store → HTTP API (/api/alerts, /api/security)
    └──▶ audit.chain (hash-linked JSONL log)
         alerts.jsonl (flat log)
```

### Runtime

- **Tokio** async runtime (`tokio::runtime::Runtime::new().block_on(async_main())`)
- Root privilege escalation happens in `main()` *before* tokio starts (so sudo password prompt works)
- Each source is a `tokio::spawn`ed task
- Blocking scans use `tokio::task::spawn_blocking`

### Module List

| Module | Purpose |
|--------|---------|
| `main.rs` | Entry point, CLI dispatch, spawns all tasks, wires channels |
| `alerts.rs` | `Alert`, `Severity`, `AlertStore` ring buffer types |
| `aggregator.rs` | Deduplication (fuzzy shape matching), per-source rate limiting |
| `config.rs` | TOML config deserialization (`Config` struct with all sections) |
| `admin.rs` | Admin key generation (Argon2), verification, Unix socket for authenticated commands |
| `audit_chain.rs` | Hash-linked integrity log (SHA-256 chain, tamper-evident) |
| `auditd.rs` | Audit log parser (SYSCALL/EXECVE/AVC records), aarch64 syscall table, user filtering |
| `behavior.rs` | Hardcoded behavioral detection rules (~200 patterns across 5 threat categories) |
| `cognitive.rs` | Cognitive file protection — SHA-256 baselines for identity files (SOUL.md, etc.) |
| `secureclaw.rs` | Pattern engine loading 4 JSON databases (injection, dangerous commands, privacy, supply chain) |
| `sentinel.rs` | Real-time file watching via `notify` (inotify), shadow copies, quarantine, content scanning |
| `scanner.rs` | 30+ periodic security scans (firewall, auditd, SUID, packages, docker, NTP, etc.) |
| `policy.rs` | YAML-based policy engine for detection (distinct from clawsudo enforcement) |
| `netpolicy.rs` | Network policy engine (allowlist/blocklist mode for outbound connections) |
| `network.rs` | iptables log line parser, CIDR/port allowlisting |
| `journald.rs` | Journalctl-based log sources (kernel messages for network, SSH login events) |
| `falco.rs` | Falco JSON log parser (eBPF-based syscall monitoring) |
| `samhain.rs` | Samhain FIM log parser |
| `firewall.rs` | Periodic UFW status monitoring with diff-based change detection |
| `logtamper.rs` | Audit log integrity monitor (size decrease, inode change, permissions) |
| `slack.rs` | Slack webhook notifier (primary + backup webhook, heartbeat) |
| `tui.rs` | Ratatui TUI dashboard (6 tabs: Alerts, Network, Falco, FIM, System, Config editor) |
| `api.rs` | HTTP API server (hyper, endpoints: `/api/status`, `/api/alerts`, `/api/security`, `/api/health`) |
| `proxy.rs` | API key proxy with DLP scanning (virtual→real key mapping, SSN/credit card/AWS key detection) |
| `update.rs` | Self-updater (GitHub releases, SHA-256 + Ed25519 signature verification, chattr dance) |
| `bin/clawsudo.rs` | Standalone sudo gatekeeper binary with YAML policy evaluation and Slack approval flow |

---

## Module Guide

### `main.rs`

**Entry point and orchestrator.** Handles:
- CLI subcommand dispatch (`run`, `scan`, `update`, `configure`, `setup`, `harden`, `uninstall`, `verify-key`, `verify-audit`, `status`, `logs`, `sync`)
- Root privilege escalation via `ensure_root()` (re-execs with `sudo` before tokio starts)
- Channel creation (3-stage pipeline: `raw_tx` → aggregator → `alert_tx` + `slack_tx`)
- Spawning all monitoring tasks based on config
- TUI mode vs headless mode
- Service stop/restart when entering/exiting TUI mode

**Key functions:** `main()`, `async_main()`, `ensure_root()`, `print_help()`, `run_script()`, `find_scripts_dir()`

### `alerts.rs`

Core types used everywhere:
- `Severity` — `Info`, `Warning`, `Critical` (with `Ord` for comparison)
- `Alert` — timestamp + severity + source + message (serializable)
- `AlertStore` — Vec-based ring buffer with `push()`, `alerts()`, `count_by_severity()`

### `aggregator.rs`

Sits between raw sources and consumers. Two mechanisms:
1. **Fuzzy dedup** — Replaces all ASCII digits with `#` to create a "shape" key (so "Found 3 issues for uid 1000" and "Found 4 issues for uid 1000" are the same shape). 30s window for normal alerts, 1h for `scan:*` sources.
2. **Per-source rate limiting** — Max 20 alerts per source per 60s window.

Critical alerts have a much tighter 5s dedup window and bypass rate limiting.

Also handles: JSONL log persistence, audit chain appending, JSONL log rotation (>10MB), API store forwarding.

**Key struct:** `Aggregator` with `process(Alert) -> Option<Alert>`

### `config.rs`

Deserializes TOML config into `Config` struct. Sections:
- `general` — `watched_user`/`watched_users`/`watch_all_users`, `min_alert_level`, `log_file`
- `slack` — webhook URLs, channel, `min_slack_level`, `heartbeat_interval`
- `auditd` — `enabled`, `log_path`
- `network` — `enabled`, `log_path`, `log_prefix`, `source` (auto/journald/file), allowlisted CIDRs/ports
- `falco` — `enabled`, `log_path`
- `samhain` — `enabled`, `log_path`
- `ssh` — `enabled`
- `api` — `enabled`, `bind`, `port`
- `scans` — `interval` (seconds)
- `proxy` — `enabled`, `bind`, `port`, `key_mapping[]`, `dlp.patterns[]`
- `policy` — `enabled`, `dir`
- `secureclaw` — `enabled`, `vendor_dir`
- `netpolicy` — `enabled`, `mode` (allowlist/blocklist), `allowed_hosts`, `allowed_ports`, `blocked_hosts`
- `sentinel` — `enabled`, `watch_paths[]` (path + patterns + policy), `quarantine_dir`, `shadow_dir`, `debounce_ms`, `scan_content`, `max_file_size_kb`
- `auto_update` — `enabled`, `interval`

**Key method:** `Config::load(path)`, `Config::save(path)`
**Helper:** `GeneralConfig::effective_watched_users()` handles backward compat (`watched_user` singular → `watched_users` list)

### `admin.rs`

Admin key system:
- Keys are `OCAV-` + 64 hex chars (256 bits), hashed with **Argon2**
- `init_admin_key()` — Generates key on first run, displays it once, stores only the hash
- `AdminSocket` — Unix domain socket (`/var/run/clawav/admin.sock`) for authenticated commands
- Commands: `status`, `scan`, `pause` (max 30 min), `config-update`
- Rate limiting: 3 failures → 1 hour lockout

### `audit_chain.rs`

Hash-linked integrity log:
- Each entry: `{seq, ts, severity, source, message, prev_hash, hash}`
- Hash = SHA-256 of `seq|ts|severity|source|message|prev_hash`
- Genesis entry uses all-zeros prev_hash
- `AuditChain::verify(path)` validates entire chain
- CLI: `clawav verify-audit [path]`

### `auditd.rs`

Parses Linux audit log (`/var/log/audit/audit.log`):
- `ParsedEvent` struct with syscall_name, command, args, file_path, success, actor, ppid_exe
- `Actor` enum: Agent (auid=4294967295/unset), Human (auid set), Unknown
- aarch64 syscall number → name mapping (60+ syscalls)
- Hex-encoded argument decoding
- User filtering (only watched users, but tamper events bypass filter)
- `check_tamper_event()` — detects `key="clawav-tamper"` and `key="clawav-config"` auditd keys
- Pipeline: `parse_to_event()` → behavior/policy/secureclaw checks → `event_to_alert()`

### `behavior.rs`

Hardcoded behavioral threat detection with 5 categories:
1. **DataExfiltration** — curl/wget/nc to non-safe hosts, DNS exfiltration, memory dumps, tunnels, encoding+piping
2. **PrivilegeEscalation** — reading /etc/shadow, writing /etc/passwd, container escapes, SSH key injection, ptrace
3. **SecurityTamper** — disabling firewalls/services, persistence (crontab/systemd/init.d), log clearing, binary replacement, history tampering
4. **Reconnaissance** — whoami, id, uname, env, reading .env/.aws/.ssh files
5. **SideChannel** — mastik, flush-reload, prime-probe, perf_event_open

Has allowlists for safe hosts, normal system operations (`ip neigh`, `crontab -l`), and build tool suppression (cargo/gcc child processes don't trigger LD_PRELOAD bypass alerts).

### `cognitive.rs`

Protects AI agent identity files:
- **Protected files** (CRIT on change): `SOUL.md`, `IDENTITY.md`, `TOOLS.md`, `AGENTS.md`, `USER.md`, `HEARTBEAT.md`
- **Watched files** (INFO with diff): `MEMORY.md`
- SHA-256 baselines stored in `/etc/clawav/cognitive-baselines.sha256`
- Shadow copies in `/etc/clawav/cognitive-shadow/` for diff generation
- Watched files auto-rebaseline on clean changes
- SecureClaw content scanning only on protected files (watched files contain too many false positives)

### `secureclaw.rs`

Pattern engine loading 4 JSON databases from `vendor/secureclaw/`:
1. **injection-patterns.json** — Prompt injection patterns (by category)
2. **dangerous-commands.json** — Dangerous command patterns (by category with severity/action)
3. **privacy-rules.json** — PII/privacy regex rules
4. **supply-chain-ioc.json** — Suspicious skill patterns, ClawHavoc C2 indicators

**Key struct:** `SecureClawEngine` with `check_text()`, `check_command()`, `check_privacy()`

`check_command()` has a large `SUDO_ALLOWLIST` (100+ entries) for legitimate system commands that happen to match "sudo" patterns.

### `sentinel.rs`

Real-time file watcher using `notify` (inotify on Linux):
- Watches parent directories of configured paths
- Per-path policy: `Protected` (quarantine + restore from shadow) or `Watched` (update shadow, info alert)
- Shadow copies stored at `shadow_dir / hex(sha256(path))[..16]_filename`
- Quarantine copies at `quarantine_dir / timestamp_filename`
- Content scanning via SecureClaw if `scan_content: true`
- Log rotation detection (skips changes when `.1`/`.gz`/`.0` siblings exist)
- Debouncing (configurable, default 200ms)

### `scanner.rs`

30+ periodic security scans running via `spawn_blocking`:

| Scan | What it checks |
|------|---------------|
| `firewall` | UFW active + rule count |
| `auditd` | Enabled, immutable mode, rule count |
| `integrity` | SHA-256 checksums of binary + config |
| `immutable_flags` | `chattr +i` on critical ClawAV files |
| `apparmor_protection` | AppArmor profiles loaded |
| `secureclaw_sync` | SecureClaw pattern age |
| `audit_log` | Log file permissions + existence |
| `cognitive` | Identity file baselines |
| `crontab_audit` | Suspicious cron entries |
| `world_writable` | World-writable files in sensitive dirs |
| `suid_sgid` | SUID/SGID binaries vs known-safe list |
| `kernel_modules` | Suspicious module names |
| `docker_security` | Privileged containers, socket exposure |
| `password_policy` | PASS_MAX_DAYS, PAM quality checking |
| `open_fds` | Suspicious network connections |
| `dns_resolver` | Unusual DNS servers |
| `ntp_sync` | Time synchronization status |
| `failed_logins` | SSH brute force detection |
| `process_health` | Zombie processes, high CPU |
| `swap_tmpfs` | /tmp noexec, /dev/shm security |
| `environment_vars` | LD_PRELOAD, credentials in env |
| `package_integrity` | dpkg --verify |
| `core_dumps` | Core dump configuration |
| `network_interfaces` | Promiscuous mode, tunnels, IP forwarding |
| `systemd_hardening` | Service file security features |
| `user_accounts` | UID 0 users, passwordless shells, sudo group |
| `sidechannel` | CPU vulnerability mitigations |
| `openclaw:*` | Gateway exposure, auth, workspace scope, VPN/tunnel |
| `updates` | Pending apt updates |
| `ssh` | SSH daemon running |
| `listening` | Unexpected listening services |
| `resources` | Disk usage |

**Key types:** `ScanResult` (category, status, details, timestamp), `ScanStatus` (Pass/Warn/Fail)
**Integration:** `ScanResult::to_alert()` converts Warn→Warning, Fail→Critical
**Note:** Function names and category names sometimes differ (e.g., `scan_zombie_processes()` → category `"process_health"`, `scan_open_file_descriptors()` → category `"open_fds"`)

### `policy.rs`

YAML-based detection policy engine (distinct from `clawsudo.rs` enforcement):
- Rules have `match` spec: `command` (exact binary), `command_contains` (substring), `file_access` (glob), `exclude_args` (whitelist)
- Actions: `critical`, `warning`, `info`, `block`
- Highest-severity match wins
- `clawsudo*.yaml` files are explicitly skipped (those are enforcement-only)

### `proxy.rs`

API key proxy + DLP scanner:
- Virtual→real key mapping (agents never see real API keys)
- Provider-aware header rewriting (Anthropic `x-api-key` vs OpenAI `Authorization: Bearer`)
- DLP patterns: `block` (reject request) or `redact` (replace with `[REDACTED]`)

### `update.rs`

Self-update system:
- Checks GitHub releases API (`coltz108/ClawAV`)
- Downloads platform-specific binary (`clawav-aarch64-linux` or `clawav-x86_64-linux`)
- Verifies SHA-256 checksum (required) + Ed25519 signature (optional, key embedded at compile time)
- Binary replacement: `chattr -i` → write temp → rename → `chattr +i`
- Custom binary install requires admin key; GitHub releases don't (checksum is trust anchor)
- Background auto-updater runs every `auto_update.interval` seconds (default 300)
- `is_newer_version()` compares semver numerically

### `tui.rs`

Ratatui-based terminal UI with 6 tabs:
- **Alerts** — All alerts, color-coded by severity
- **Network** — Network source alerts
- **Falco** — Falco eBPF alerts
- **FIM** — Samhain file integrity alerts
- **System** — Status dashboard (version, alert counts)
- **Config** — Interactive config editor (sidebar sections + field editor, Ctrl+S to save with sudo support)

Has a sudo popup modal for privileged operations (saving config to immutable files, installing Falco/Samhain).

**Config editor sections:** general, slack, auditd, network, falco, samhain, api, scans, proxy, policy, secureclaw, netpolicy. Note: `sentinel`, `ssh`, and `auto_update` are NOT exposed in the TUI config editor.

### `bin/clawsudo.rs`

Standalone binary — sudo gatekeeper:
- Loads YAML policies from `/etc/clawav/policies/` and `./policies/`
- Evaluates command against rules → Allow, Deny, or Ask
- **Fail-secure**: no rules → deny all
- Ask mode: creates `/tmp/clawsudo-<hash>.approved` file, sends Slack message, polls for 5 min
- Logs all decisions to `/var/log/clawav/clawsudo.log` and audit chain
- Exit codes: 0 (ok), 1 (fail), 77 (denied), 78 (timeout)

---

## Key Patterns

### Alert Pipeline (mpsc channels)

```rust
let (raw_tx, raw_rx) = mpsc::channel::<Alert>(1000);   // Sources → Aggregator
let (alert_tx, alert_rx) = mpsc::channel::<Alert>(1000); // Aggregator → TUI
let (slack_tx, slack_rx) = mpsc::channel::<Alert>(100);  // Aggregator → Slack
```

Sources `clone()` `raw_tx` and send alerts. The aggregator deduplicates, rate-limits, and fans out to TUI, Slack, API store, and audit chain.

### Scanner System

Each scan is a sync function returning `ScanResult`. All scans run via `spawn_blocking` in `SecurityScanner::run_all_scans()`. Results are stored in `SharedScanResults` (Arc<Mutex<Vec<ScanResult>>>) and converted to alerts via `ScanResult::to_alert()` (Pass produces no alert).

### SecureClaw Pattern Engine

Loads 4 JSON files from `vendor_dir`:
- `injection-patterns.json` — `{patterns: {category: [regex...]}}`
- `dangerous-commands.json` — `{categories: {name: {severity, action, patterns: [regex...]}}}`
- `privacy-rules.json` — `{rules: [{id, regex, severity, action}]}`
- `supply-chain-ioc.json` — `{suspicious_skill_patterns: [regex...], clawhavoc: {name_patterns, c2_servers}}`

Invalid regex patterns are logged and skipped (graceful degradation).

### Sentinel (Real-time File Watching)

Uses `notify::RecommendedWatcher` (inotify). Watches parent directories, filters events by configured paths. Two policies:
- **Protected**: On change → quarantine current file, restore from shadow, send Critical alert
- **Watched**: On change → update shadow copy, send Info alert

### Cognitive File Protection

Two-tier protection for AI identity files:
- Protected files (SOUL.md, etc.) trigger Critical alerts on any change
- Watched files (MEMORY.md) auto-rebaseline and report diffs as Info/Warn
- Baselines are SHA-256 hashes persisted to `/etc/clawav/cognitive-baselines.sha256`

### Auto-updater

Background task checking GitHub releases. Flow:
1. `fetch_release(None)` → get latest tag + asset URLs
2. `is_newer_version(current, remote)` → compare semver
3. `download_and_verify()` → download + SHA-256 check
4. `verify_release_signature()` → Ed25519 (if .sig exists)
5. Write to temp file → `chattr -i` → `rename` → `chattr +i`
6. Notify Slack → `systemctl restart clawav`

### Admin Key Authentication

- Key format: `OCAV-` + 64 hex chars
- Hashed with Argon2 (salt from OsRng)
- Stored at `/etc/clawav/admin.key.hash`
- Rate limited: 3 failures → 1 hour lockout
- Used for: self-update (custom binary only), uninstall, admin socket commands

### Audit Chain

Append-only hash-linked log. Each entry's hash covers `seq|ts|severity|source|message|prev_hash`. Tamper-evident: modifying any entry breaks the chain. Verified via `clawav verify-audit`.

---

## Configuration

Config file: `/etc/clawav/config.toml` (TOML format)

```toml
[general]
watched_users = ["openclaw"]  # or watch_all_users = true
min_alert_level = "info"
log_file = "/var/log/clawav/clawav.log"

[slack]
enabled = true
webhook_url = "https://hooks.slack.com/services/..."
backup_webhook_url = ""
channel = "#security"
min_slack_level = "warning"
heartbeat_interval = 3600  # seconds, 0 to disable

[auditd]
enabled = true
log_path = "/var/log/audit/audit.log"

[network]
enabled = true
log_path = "/var/log/syslog"
log_prefix = "CLAWAV_NET"
source = "auto"  # auto|journald|file
allowlisted_cidrs = ["192.168.0.0/16", "10.0.0.0/8", ...]
allowlisted_ports = [443, 53, 123, 5353]

[falco]
enabled = false
log_path = "/var/log/falco/falco_output.jsonl"

[samhain]
enabled = false
log_path = "/var/log/samhain/samhain.log"

[ssh]
enabled = true

[api]
enabled = false
bind = "0.0.0.0"
port = 18791

[scans]
interval = 300  # seconds between scan cycles

[proxy]
enabled = false
bind = "127.0.0.1"
port = 18790
[[proxy.key_mapping]]
virtual_key = "vk-anthropic-001"
real = "sk-ant-api03-REAL"
provider = "anthropic"
upstream = "https://api.anthropic.com"
[[proxy.dlp.patterns]]
name = "ssn"
regex = "\\b\\d{3}-\\d{2}-\\d{4}\\b"
action = "block"

[policy]
enabled = true
dir = "./policies"

[secureclaw]
enabled = false
vendor_dir = "./vendor/secureclaw/secureclaw/skill/configs"

[netpolicy]
enabled = false
mode = "blocklist"  # allowlist|blocklist
allowed_hosts = []
allowed_ports = [80, 443, 53]
blocked_hosts = []

[sentinel]
enabled = true
quarantine_dir = "/etc/clawav/quarantine"
shadow_dir = "/etc/clawav/sentinel-shadow"
debounce_ms = 200
scan_content = true
max_file_size_kb = 1024
[[sentinel.watch_paths]]
path = "/home/openclaw/.openclaw/workspace/SOUL.md"
patterns = ["*"]
policy = "protected"

[auto_update]
enabled = true
interval = 300
```

---

## Testing

### Running Tests

```bash
cargo test                    # All tests
cargo test -- --nocapture     # With stdout
cargo test test_name          # Specific test
cargo test --release          # Release mode
```

### Test Organization

Tests are inline `#[cfg(test)] mod tests` in each module. Key test areas:

| Module | Tests Cover |
|--------|-------------|
| `aggregator` | Dedup, rate limiting, fuzzy shape matching, critical bypass |
| `auditd` | Syscall parsing, EXECVE decoding, hex args, user filtering, tamper detection, actor attribution |
| `behavior` | 40+ tests covering all threat categories, false positive suppression, build tool allowlisting |
| `scanner` | UFW parsing, auditctl parsing, disk usage, immutable flags, sidechannel mitigations |
| `secureclaw` | Engine loading, command checking, privacy checking, graceful missing files, crontab grep suppression |
| `sentinel` | Shadow path uniqueness, diff generation, log rotation, protected quarantine+restore, watched file updates |
| `cognitive` | Baseline creation, modification/deletion/new file detection, save/load, rebaseline |
| `audit_chain` | Genesis entry, chain verification, tamper detection, resume from file |
| `policy` | YAML parsing, command/file/substring matching, exclude_args, severity priority |
| `proxy` | Virtual key lookup, DLP block/redact/pass |
| `admin` | Key generation, verification, rate limiter lockout/reset |
| `update` | Version comparison, asset naming, admin key flags, signature validation |
| `clawsudo` | Policy evaluation (apt allowed, bash denied, ufw disable denied, unknown = ambiguous) |
| `network` | CIDR/port allowlisting, LAN/public/docker traffic |
| `netpolicy` | Allowlist/blocklist modes, wildcard matching, URL extraction |
| `falco/samhain` | Log line parsing |
| `api` | Ring buffer capacity, JSON serialization, severity counting |
| `firewall` | Active detection, diff generation |
| `logtamper` | Missing log, truncation, first check |

### Dev Dependencies

- `tempfile = "3"` — Used extensively for test directories

---

## Build & Deploy

### Building

```bash
cargo build                           # Debug
cargo build --release                 # Release (stripped, LTO, opt-level=z)
```

Release profile: `strip = true`, `lto = true`, `opt-level = "z"` (size optimized).

### CI/CD (GitHub Actions)

**`ci.yml`** — On push to `main` and PRs:
- `cargo build --release`
- `cargo test`
- `cargo clippy` (warnings, non-blocking)

**`release.yml`** — On tag push (`v*`):
- Cross-compiles for `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`
- Builds both `clawav` and `clawsudo` binaries
- Generates SHA-256 checksums per artifact
- Creates GitHub release with binaries + checksums

### Release Signing

- Ed25519 signing key: private key held by maintainer, public key embedded at `src/release-key.pub` (32 bytes, compiled in via `include_bytes!`)
- Signature file: `clawav-<arch>-linux.sig` (64 bytes, signs SHA-256 of binary)
- Auto-updater verifies signature if `.sig` asset exists, warns if missing

### Installation

```bash
# One-shot install from GitHub release
curl -sSL https://raw.githubusercontent.com/coltz108/ClawAV/main/scripts/oneshot-install.sh | sudo bash

# From source
clawav setup --source --auto

# Manual
cargo build --release
sudo scripts/install.sh
sudo scripts/setup-auditd.sh
sudo scripts/setup-iptables.sh
```

### Key Scripts

| Script | Purpose |
|--------|---------|
| `setup.sh` | Full installation (copy binary, create dirs, systemd service) |
| `install.sh` | Apply tamper-proof hardening (chattr, sudoers deny) |
| `configure.sh` | Interactive config wizard |
| `uninstall.sh` | Reverse hardening + remove (requires admin key) |
| `setup-auditd.sh` | Install auditd rules for ClawAV monitoring |
| `setup-audit-rules.sh` | Configure specific audit rules (syscall watches, tamper keys) |
| `setup-iptables.sh` | Configure iptables logging |
| `setup-apparmor.sh` | Load AppArmor profiles |
| `setup-falco.sh` | Install and configure Falco eBPF monitoring |
| `setup-samhain.sh` | Install and configure Samhain file integrity monitoring |
| `setup-slack.sh` | Configure Slack webhook integration |
| `setup-sudoers-deny.sh` | Install sudoers deny rules preventing agent from stopping ClawAV |
| `build-preload.sh` | Compile `libclawguard.so` LD_PRELOAD guard library |
| `enable-preload.sh` | Install and activate the LD_PRELOAD guard |
| `sync-secureclaw.sh` | Update SecureClaw pattern databases |
| `oneshot-install.sh` | Single-command install from GitHub |

---

## Additional Public API Details

The following public items are used internally and may be relevant when extending ClawAV:

### `api.rs`
- **`AlertRingBuffer`** — Fixed-capacity ring buffer for the HTTP API alert store
- **`SharedAlertStore`** — Type alias: `Arc<Mutex<AlertRingBuffer>>`
- **`new_shared_store(max)`** — Constructor for `SharedAlertStore`

### `scanner.rs`
- **`SharedScanResults`** — Type alias: `Arc<Mutex<Vec<ScanResult>>>`
- **`new_shared_scan_results()`** — Constructor for `SharedScanResults`
- **`SecurityScanner`** — Unit struct with `run_all_scans()` static method
- **`parse_ufw_status(output)`** — Parses `ufw status` output into a `ScanResult`
- **`parse_auditctl_status(output)`** — Parses `auditctl -s` output into a `ScanResult`
- **`parse_disk_usage(output)`** — Parses `df -h /` output into a `ScanResult`
- **`check_lsattr_immutable(output)`** — Returns `true` if lsattr output shows immutable flag

### `auditd.rs`
- **`extract_field(line, field)`** — Extracts a named field value from an audit log line
- **`parse_to_event(line, watched_users)`** — Parses raw audit line into `ParsedEvent`
- **`check_tamper_event(event)`** — Checks if a `ParsedEvent` is a ClawAV tamper attempt
- **`event_to_alert(event)`** — Converts a `ParsedEvent` to an `Alert`
- **`parse_audit_line(line, watched_users)`** — Full pipeline: parse + behavior/policy checks → `Alert`

### `behavior.rs`
- **`BehaviorCategory`** — Enum: `DataExfiltration`, `PrivilegeEscalation`, `SecurityTamper`, `Reconnaissance`, `SideChannel`
- **`classify_behavior(event)`** — Takes a `ParsedEvent`, returns `Option<(BehaviorCategory, Severity)>`

### `cognitive.rs`
- **`CognitiveAlert`** — Struct: `path`, `kind`, `message`, `diff`
- **`CognitiveAlertKind`** — Enum: `Modified`, `Deleted`, `NewUnexpected`, `ContentThreat`, `BaselineMissing`
- **`scan_cognitive_integrity(workspace_dir, baseline_path, secureclaw)`** — Runs cognitive checks, returns `Vec<ScanResult>`

### `sentinel.rs`
- **`shadow_path_for(shadow_dir, file_path)`** — Computes shadow copy path from a watched file path
- **`quarantine_path_for(quarantine_dir, file_path)`** — Computes quarantine path with timestamp prefix
- **`generate_unified_diff(old, new, filename)`** — Produces unified diff string between two text contents
- **`is_log_rotation(file_path)`** — Returns `true` if the file path looks like a log rotation artifact

### `secureclaw.rs`
- **`CompiledPattern`** — Compiled regex with name and category metadata
- **`PatternMatch`** — Result of a pattern match: `pattern_name`, `category`, `matched_text`, `severity`, `action`

### `proxy.rs`
- **`DlpResult`** — Enum: `Clean`, `Blocked(String)`, `Redacted(String)` — result of DLP scanning

### `update.rs`
- **`run_update(args)`** — Entry point for the `clawav update` CLI subcommand
- **`is_newer_version(current, remote)`** — Semver comparison, returns `true` if remote is newer

### `audit_chain.rs`
- **`run_verify_audit(path)`** — CLI entry point for `clawav verify-audit [path]`

### `tui.rs`
- **`TuiEvent`** — Enum: `Key(KeyEvent)`, `Tick`, `Alert(Alert)`, `ScanResults(Vec<ScanResult>)`
- **`ConfigField`** — Struct for TUI config editor: field name, value, section, field type
- **`ConfigFocus`** — Enum: `Sections`, `Fields` — which pane has focus in config editor
- **`FieldType`** — Enum: `Text`, `Bool`, `Number`, `Select(Vec<String>)` — config field input type
- **`SudoPopup`** — Struct for the sudo password modal in TUI
- **`SudoStatus`** — Enum: `Idle`, `Waiting`, `Success`, `Failed(String)`

### `config.rs` (Sub-structs)
All config section structs are public and `Deserialize + Serialize + Default`:
`GeneralConfig`, `SlackConfig`, `AuditdConfig`, `NetworkConfig`, `FalcoConfig`, `SamhainConfig`, `SshConfig`, `ApiConfig`, `ScansConfig`, `ProxyConfig`, `KeyMapping`, `DlpConfig`, `DlpPattern`, `PolicyConfig`, `NetPolicyConfig`, `SentinelConfig`, `WatchPathConfig`, `WatchPolicy`, `AutoUpdateConfig`

- **`WatchPolicy`** — Enum: `Protected`, `Watched` — sentinel file policy
- **`default_allowlisted_cidrs()`** — Returns default LAN CIDR list for network config
- **`default_allowlisted_ports()`** — Returns default safe port list (`[443, 53, 123, 5353]`)

### `logtamper.rs`
- **`scan_audit_log_health(log_path)`** — Checks audit log for truncation, inode changes, permission issues → `ScanResult`

### `journald.rs`
- **`journald_available()`** — Returns `true` if `journalctl` is available on the system

---

## Common Tasks for LLMs

### Adding a New Scanner

1. Add a function in `src/scanner.rs`:
```rust
pub fn scan_my_check() -> ScanResult {
    // ... check logic ...
    ScanResult::new("my_check", ScanStatus::Pass, "All good")
}
```

2. Add it to `SecurityScanner::run_all_scans()`:
```rust
results.push(scan_my_check());
```

3. Add tests in the `mod tests` block.

### Adding a New Monitored Source

1. Create a new module `src/mysource.rs`
2. Add `mod mysource;` to `main.rs`
3. Implement an async function that takes `mpsc::Sender<Alert>` and sends alerts:
```rust
pub async fn tail_my_source(tx: mpsc::Sender<Alert>) -> Result<()> {
    loop {
        // ... read events ...
        let _ = tx.send(Alert::new(severity, "mysource", &message)).await;
    }
}
```
4. Spawn it in `async_main()`:
```rust
let tx = raw_tx.clone();
tokio::spawn(async move {
    if let Err(e) = mysource::tail_my_source(tx).await {
        eprintln!("mysource error: {}", e);
    }
});
```
5. Optionally add a config section in `config.rs` with an `enabled` flag.

### Adding Sentinel Watch Paths

In config TOML:
```toml
[[sentinel.watch_paths]]
path = "/path/to/file"
patterns = ["*"]
policy = "protected"  # or "watched"
```

Or modify the `Default` impl for `SentinelConfig` in `config.rs`.

### Modifying Alert Behavior

- **Change dedup window**: Modify `AggregatorConfig::default()` in `aggregator.rs`
- **Change Slack threshold**: Set `min_slack_level` in config (or `min_slack_severity` in code)
- **Add behavior rule**: Add pattern to the appropriate constant array in `behavior.rs` and handle in `classify_behavior()`
- **Add safe host for exfil detection**: Add to `SAFE_HOSTS` in `behavior.rs`
- **Add to sudo allowlist**: Add to `SecureClawEngine::SUDO_ALLOWLIST` in `secureclaw.rs`
- **Add policy rule**: Create/edit YAML in `policies/` directory

### Adding a New TUI Tab

1. Add tab title to `App::new()` `tab_titles` vec
2. Create `render_my_tab()` function
3. Add match arm in `ui()` function
4. Filter alerts by source for the tab content
