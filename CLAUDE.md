# CLAUDE.md — ClawTower LLM Onboarding Guide

> **ClawTower** is a tamper-proof, OS-level security watchdog for AI agents. It monitors the host system for threats, policy violations, and tampering — then alerts via TUI dashboard and Slack. It is designed so that even the AI agent it protects **cannot disable or modify it** (the "swallowed key" pattern).

---

## Project Overview

ClawTower continuously monitors a Linux host where an AI agent (e.g., OpenClaw) runs. It watches for:

- **Command execution** via auditd log tailing (syscalls, EXECVE records)
- **Behavioral threats** — data exfiltration, privilege escalation, reconnaissance, side-channel attacks, container escapes, persistence mechanisms, financial theft
- **File integrity** — real-time inotify-based sentinel + periodic cognitive file baselines
- **Firewall/network** — UFW state changes, iptables log parsing, network policy enforcement
- **Log tampering** — detects truncation, deletion, or inode replacement of audit logs
- **Security posture** — 30+ periodic system scans (see `docs/SECURITY-SCANNERS.md`)

### The "Swallowed Key" Pattern

Critical files are protected with `chattr +i` (immutable). The admin key (`OCAV-` + 64 hex, Argon2-hashed) is generated once, displayed, and never stored. The AI agent cannot stop ClawTower, modify its config, remove immutable flags, or escalate via sudo.

**How it actually works:** `chattr +i` is a Linux ext4 file attribute that prevents even root from modifying or deleting the file until the flag is removed. That's the entire enforcement mechanism. But root can always run `chattr -i` to remove it — so the real defense is that the AI agent doesn't have direct root access (it goes through clawsudo, which denies `chattr` on ClawTower files).

### Binaries

- **`clawtower`** — Main watchdog binary (TUI dashboard, headless daemon, scanner, updater)
- **`clawsudo`** — Sudo proxy/gatekeeper that evaluates commands against YAML policies before allowing `sudo` execution

---

## Architecture

Binary crate only (`src/main.rs`), no `lib.rs`. All modules declared as `mod` in `main.rs`.

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
```

**Runtime:** Tokio async. Root escalation in `main()` before tokio starts. Each source is a `tokio::spawn`ed task. Blocking scans use `spawn_blocking`.

### Module List

| Module | Purpose |
|--------|---------|
| `main.rs` | Entry point, CLI dispatch, spawns all tasks, wires channels |
| `alerts.rs` | `Alert`, `Severity`, `AlertStore` ring buffer types |
| `aggregator.rs` | Deduplication (fuzzy shape matching), per-source rate limiting |
| `config.rs` | TOML config deserialization (`Config` struct with all sections) |
| `config_merge.rs` | TOML config merge engine with `_add`/`_remove` list semantics for config.d/ overlays |
| `admin.rs` | Admin key generation (Argon2), verification, Unix socket for authenticated commands |
| `audit_chain.rs` | Hash-linked integrity log (SHA-256 chain, tamper-evident) |
| `auditd.rs` | Audit log parser (SYSCALL/EXECVE/AVC records), aarch64 syscall table, user filtering |
| `behavior.rs` | Hardcoded behavioral detection rules (~270 patterns across 6 threat categories) |
| `cognitive.rs` | Cognitive file protection — SHA-256 baselines for identity files (SOUL.md, etc.) |
| `barnacle.rs` | Pattern engine loading 4 JSON databases (injection, dangerous commands, privacy, supply chain) |
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

For detailed module internals, see `docs/ARCHITECTURE.md` and `docs/MONITORING-SOURCES.md`.

---

## Key Patterns & Gotchas

### Alert Pipeline

Sources `clone()` `raw_tx` and send `Alert`s. The `Aggregator` deduplicates (fuzzy shape matching — digits replaced with `#`, 30s window, 1h for scans, 5s for Critical), rate-limits (20/source/60s, Critical bypasses), and fans out to TUI, Slack, API store, and audit chain.

### Config Layering

- **Config:** base `config.toml` + `config.d/*.toml` overlays (scalar replace, list `_add`/`_remove`). See `config_merge.rs`.
- **Policies:** `default.yaml` loaded first, then alphabetical `*.yaml` files merged by rule name. `enabled: false` disables a rule.
- Updates replace base files, never touch user overrides.

### watched_users Takes UIDs, Not Usernames

`watched_users = ["1000"]` — numeric UIDs matched against auditd `uid=`/`auid=` fields. Find with `id -u <username>`.

### iptables Log Prefix Must Match Exactly

The `[network] log_prefix` in config **must exactly match** the `--log-prefix` in iptables rules from `setup-iptables.sh`. A mismatch silently drops all network alerts.

### Sentinel Policies

- **Protected**: quarantine modified file → restore from shadow → Critical alert
- **Watched**: update shadow copy → Info alert with diff

### Cognitive File Protection

- **Protected** (CRIT on change): `SOUL.md`, `IDENTITY.md`, `TOOLS.md`, `AGENTS.md`, `USER.md`, `HEARTBEAT.md`
- **Watched** (INFO with diff, auto-rebaseline): `MEMORY.md`

### Scanner Conventions

- `ScanResult` has category (snake_case), status (`Pass`/`Warn`/`Fail`), details
- `ScanResult::to_alert()` converts `Warn`→Warning, `Fail`→Critical; `Pass` produces no alert
- Function names and categories sometimes differ (e.g., `scan_zombie_processes()` → `"process_health"`)

### clawsudo (bin/clawsudo.rs)

Standalone sudo gatekeeper. Fail-secure: no rules → deny all. Exit codes: 0 (ok), 1 (fail), 77 (denied), 78 (timeout).

---

## Configuration

Config file: `/etc/clawtower/config.toml`. Full reference with all fields, types, and defaults: `docs/CONFIGURATION.md`.

**Config sections:** `general`, `slack`, `auditd`, `network`, `falco`, `samhain`, `ssh`, `api`, `scans`, `proxy`, `policy`, `barnacle`, `netpolicy`, `sentinel`, `auto_update`.

**Key methods:** `Config::load(path)`, `Config::save(path)`, `Config::load_with_overrides(base_path, config_d)`

All config section structs are public, `Deserialize + Serialize + Default`. Most in `config.rs`; `BarnacleDefenseConfig` in `barnacle.rs`.

---

## Testing

```bash
cargo test                    # All tests
cargo test -- --nocapture     # With stdout
cargo test test_name          # Specific test
```

Tests are inline `#[cfg(test)] mod tests` in each module. Dev dependency: `tempfile = "3"`.

**PATH note:** If `cargo` is not found, source the Rust environment first: `export PATH="$HOME/.cargo/bin:$PATH"` (or `source "$HOME/.cargo/env"`).

---

## Build & Deploy

```bash
cargo build --release         # Release (strip=true, lto=true, opt-level=z)
```

**CI:** `ci.yml` runs build + test + clippy on push/PR. `release.yml` cross-compiles for x86_64 + aarch64 on tag push, generates checksums, creates GitHub release.

**Release signing:** Ed25519 key embedded at `src/release-key.pub`. Auto-updater verifies `.sig` if present.

**Install:** `curl -sSL .../oneshot-install.sh | sudo bash` or `clawtower setup --source --auto`. Scripts in `scripts/` directory.

### Remote Deploy & Pentest

Two gitignored scripts automate deploying to the target machine (`claw` = `192.168.1.85`):

```bash
./scripts/deploy.sh           # Deploy ARM binary to remote (sshpass as jr, chattr dance)
./scripts/deploy.sh --build   # Cross-compile for aarch64 first, then deploy
./scripts/pentest.sh           # Ship & run latest Red Lobster suite as openclaw
./scripts/pentest.sh v7        # Run a specific version
./scripts/pentest.sh v8 flag15 # Pass args to run-all.sh
```

- `deploy.sh` cross-compiles for `aarch64-unknown-linux-gnu`, uploads binary + config + policies, stops the service, does the `chattr -i` → replace → `chattr +i` immutable dance, restarts. **Gitignored** (contains credentials).
- `pentest.sh` auto-detects the highest `redlobster-v*-run-all.sh`, ships all scripts for that version + `redlobster-lib.sh` to the remote, and runs as `openclaw`. **Gitignored** (contains credentials).

### Pre-Push Checklist

**Before pushing, always run deploy + pentest to verify on the target machine:**

```bash
cargo test                     # 1. Unit tests pass locally
cargo build --release --target aarch64-unknown-linux-gnu  # 2. Release build succeeds
./scripts/deploy.sh            # 3. Deploy to remote
./scripts/pentest.sh           # 4. Red Lobster pentest suite passes on remote
```

Do not push until steps 3 and 4 succeed. If the pentest reveals regressions, fix them before pushing.

---

## Common Tasks for LLMs

### Adding a New Scanner

1. Add scan function in `src/scanner.rs` returning `ScanResult`:

```rust
pub fn scan_my_check() -> ScanResult {
    // Use run_cmd() for external commands (30s timeout), run_cmd_with_sudo() for privileged
    // Return ScanResult::new("my_check", ScanStatus::Pass|Warn|Fail, "details")
    // Use Warn (not Fail) when tools are unavailable
}
```

2. Register in `SecurityScanner::run_all_scans()` results vec
3. Add tests — category appears in alerts as `scan:my_check`

### Adding a New Monitoring Source

1. Create `src/my_source.rs` with a `pub async fn tail_...(tx: mpsc::Sender<Alert>)` function
2. Add `mod my_source;` in `main.rs`
3. Spawn in `async_main()`: `tokio::spawn(async move { my_source::tail_...(raw_tx.clone()).await; });`
4. Optionally add config section (struct with `enabled: bool`, add to `Config`, gate spawn)

See `docs/MONITORING-SOURCES.md` for full patterns and existing source implementations.

### Adding Sentinel Watch Paths

```toml
[[sentinel.watch_paths]]
path = "/path/to/file"
patterns = ["*"]
policy = "protected"  # or "watched"
```

To add compile-time defaults, modify `SentinelConfig::default()` in `src/config.rs`.

### Modifying Alert Behavior

- **Dedup window**: `AggregatorConfig::default()` in `aggregator.rs`
- **Slack threshold**: `min_slack_level` in config
- **Behavior rule**: Add pattern to constant array in `behavior.rs`, handle in `classify_behavior()`
- **Safe host**: Add to `SAFE_HOSTS` in `behavior.rs`
- **Sudo allowlist**: Add to `BarnacleDefenseEngine::SUDO_ALLOWLIST` in `barnacle.rs`
- **Policy rule**: Create/edit YAML in `policies/` directory

### Adding a New TUI Tab

1. Add tab title to `App::new()` `tab_titles` vec
2. Create `render_my_tab()` function
3. Add match arm in `ui()` function
4. Note: `sentinel`, `ssh`, `auto_update` are NOT exposed in the TUI config editor

---

## See Also

| Document | Description |
|----------|-------------|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Module dependency graph, data flow diagrams, threat model |
| [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) | Full config reference — every field, type, default, and TOML example |
| [`docs/ALERT-PIPELINE.md`](docs/ALERT-PIPELINE.md) | Alert model, pipeline architecture, aggregator tuning |
| [`docs/SENTINEL.md`](docs/SENTINEL.md) | Real-time file integrity monitoring deep dive |
| [`docs/SECURITY-SCANNERS.md`](docs/SECURITY-SCANNERS.md) | All 30+ periodic security scanners |
| [`docs/MONITORING-SOURCES.md`](docs/MONITORING-SOURCES.md) | Every real-time data source (auditd, journald, falco, samhain, etc.) |
| [`docs/POLICIES.md`](docs/POLICIES.md) | YAML policy writing guide |
| [`docs/CLAWSUDO-AND-POLICY.md`](docs/CLAWSUDO-AND-POLICY.md) | clawsudo, admin key, audit chain, API proxy, LD_PRELOAD guard |
| [`docs/API.md`](docs/API.md) | HTTP REST API endpoints and response formats |
| [`docs/INSTALL.md`](docs/INSTALL.md) | Installation, hardening steps, CLI commands, recovery |
| [`docs/openclaw-integration.md`](docs/openclaw-integration.md) | OpenClaw security integration |