# Alert Pipeline Architecture

Complete guide to ClawTower's alert and monitoring pipeline — from event sources through aggregation to delivery.

## Table of Contents

- [Alert Model](#alert-model)
- [Pipeline Architecture](#pipeline-architecture)
- [Alert Sources](#alert-sources)
- [Aggregator](#aggregator)
- [Slack Integration](#slack-integration)
- [TUI Dashboard](#tui-dashboard)
- [Tuning Alerts](#tuning-alerts)

---

## Alert Model

Every monitoring subsystem in ClawTower produces `Alert` values — the universal currency of the system.

### The `Alert` Struct

```rust
pub struct Alert {
    pub timestamp: DateTime<Local>,  // When the alert was created (local time)
    pub severity: Severity,          // Info, Warning, or Critical
    pub source: String,              // Which module generated it (e.g., "auditd", "scan:firewall")
    pub message: String,             // Human-readable description
}
```

Alerts are created with `Alert::new(severity, source, message)`, which automatically timestamps to `Local::now()`.

They serialize to JSON (via `serde::Serialize`) for JSONL logging and the API, and implement `Display` for the TUI:

```
[14:23:07] WARN [auditd] exec: curl http://suspicious.example.com
```

### Severity Levels

Three levels, ordered lowest to highest (`Severity` implements `Ord`):

| Level | Display | Emoji | Slack Color | Use |
|-------|---------|-------|-------------|-----|
| `Info` | `INFO` | ℹ️ | `#36a64f` (green) | Normal operational events |
| `Warning` | `WARN` | ⚠️ | `#daa520` (gold) | Suspicious activity, policy violations |
| `Critical` | `CRIT` | 🔴 | `#dc3545` (red) | Active threats, tampering, privilege escalation |

Severity is parsed from config strings via `Severity::from_str()` (case-insensitive, accepts "critical"/"crit", "warning"/"warn"; anything else defaults to `Info`).

### AlertStore

The `AlertStore` is a bounded ring buffer used by the TUI to hold the most recent alerts in memory:

- Default capacity: **500 alerts**
- When full, the oldest alert is evicted (FIFO)
- Provides `count_by_severity()` for the System status panel

---

## Pipeline Architecture

```
┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
│  auditd  │  │ sentinel │  │ firewall │  │ scanner  │  │  falco   │  ... more sources
└────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘
     │             │             │             │             │
     └──────┬──────┴──────┬──────┴──────┬──────┴──────┬──────┘
            │             │             │             │
            ▼             ▼             ▼             ▼
         ┌─────────────────────────────────────────────┐
         │              raw_tx (capacity: 1000)        │
         └──────────────────────┬──────────────────────┘
                                │
                                ▼
         ┌─────────────────────────────────────────────┐
         │               AGGREGATOR                    │
         │  • Fuzzy deduplication (30s / 1h window)    │
         │  • Per-source rate limiting (20/min)        │
         │  • Critical bypass (5s dedup only)          │
         │  • JSONL logging + audit chain append       │
         │  • API store update                         │
         └──────┬───────────────────┬──────────────────┘
                │                   │
                ▼                   ▼
   ┌────────────────────┐  ┌───────────────┐
   │ alert_tx (cap 1000)│  │ slack_tx (100)│  ← only if severity >= min_slack_level
   └────────┬───────────┘  └───────┬───────┘
            │                      │
            ▼                      ▼
   ┌────────────────────┐  ┌───────────────┐
   │   TUI / headless   │  │ SlackNotifier │
   │   (AlertStore)     │  │ (webhook POST)│
   └────────────────────┘  └───────────────┘
```

### Channel Wiring (from `main.rs`)

```rust
let (raw_tx, raw_rx) = mpsc::channel::<Alert>(1000);   // Sources → Aggregator
let (alert_tx, alert_rx) = mpsc::channel::<Alert>(1000); // Aggregator → TUI/headless
let (slack_tx, slack_rx) = mpsc::channel::<Alert>(100);   // Aggregator → Slack
```

Each source receives a `raw_tx.clone()`. The aggregator task consumes `raw_rx`, filters alerts, then fans out to both `alert_tx` (for TUI/headless display) and `slack_tx` (for Slack delivery, gated by `min_slack_severity`).

### Headless Mode

With `--headless`, instead of starting the TUI, alerts are drained from `alert_rx` and printed to stderr:

```
[WARN] [auditd] exec: curl http://suspicious.example.com
```

---

## Alert Sources

Every component below receives a `raw_tx: mpsc::Sender<Alert>` clone and sends alerts into the pipeline.

### auditd (`src/auditd.rs`)

- **Source tag**: `"auditd"`
- Tails the Linux audit log (default: `/var/log/audit/audit.log`)
- Reports syscall-level events: exec, file access, privilege changes
- Integrates with **behavior** detection and **policy** evaluation inline
- Requires root for audit log access; gracefully skips if unreadable
- Config: `[auditd]` section — `enabled`, `log_path`

### behavior (`src/behavior.rs`)

- **Source tag**: `"behavior"`
- Classifies audit events against known attack patterns (e.g., reverse shells, data exfiltration)
- Called inline from the auditd tail loop, not a separate task
- Produces `Warning` or `Critical` alerts depending on pattern match confidence

### behavior detector adapter (shadow mode)

- When `[behavior].detector_shadow_mode = true`, auditd also evaluates the detector abstraction path in parallel
- Production behavior alerts continue to come from the legacy path during shadow mode
- Parity drift emits `parity:behavior` `Info` diagnostics (deduped in-source)
- Counters are exposed via API: `parity.mismatches_total`, `parity.alerts_emitted`, `parity.alerts_suppressed`

### sentinel (`src/sentinel.rs`)

- **Source tag**: `"sentinel"`
- Real-time file integrity monitoring using filesystem notifications (inotify)
- Supports quarantine and restore of modified files
- Integrates with BarnacleDefense pattern matching for content scanning
- Config: `[sentinel]` section — `enabled` + watched paths

### firewall (`src/firewall.rs`)

- **Source tag**: `"firewall"` or `"scan:firewall"`
- Monitors UFW/iptables rule changes and firewall disablement
- Runs as its own spawned task (`firewall::monitor_firewall`)

### logtamper (`src/logtamper.rs`)

- **Source tag**: `"logtamper"`
- Detects audit log truncation, replacement, or permission changes
- Polls every 30 seconds (configurable) comparing file size/inode
- Only runs if auditd is enabled and the log is readable

### network (`src/network.rs`)

- **Source tag**: `"network"`
- Tails firewall log entries from a file (e.g., `/var/log/kern.log`)
- Filters by configurable log prefix (e.g., `"[UFW BLOCK]"`)
- Config: `[network]` section — `enabled`, `log_path`, `log_prefix`, `source`

### journald (`src/journald.rs`)

- **Source tag**: `"network"` (for network) or `"ssh"` (for SSH login monitoring)
- Alternative to file-based network monitoring; reads from systemd journal
- Auto-detected: prefers journald, falls back to file if unavailable
- Also monitors SSH login events when `[ssh]` is enabled in config
- SSH monitoring classifies: `Accepted` → Info, `Failed password`/`Failed publickey` → Warning, `Invalid user` → Warning

### falco (`src/falco.rs`)

- **Source tag**: `"falco"`
- Tails Falco eBPF security tool output
- Config: `[falco]` section — `enabled`, `log_path`
- TUI Config tab can install Falco via action button

### samhain (`src/samhain.rs`)

- **Source tag**: `"samhain"`
- Tails Samhain file integrity monitor output
- Config: `[samhain]` section — `enabled`, `log_path`
- TUI Config tab can install Samhain via action button

### scanner (`src/scanner.rs`)

- **Source tag**: `"scan:<category>"` (e.g., `"scan:cron"`, `"scan:suid"`, `"scan:ssh"`)
- Periodic security posture scans (30+ checks)
- Runs on a configurable interval (default in `[scans]` section)
- One-shot mode available via `clawtower scan`
- Scan-prefixed sources use a longer dedup window (1 hour) in the aggregator

### cognitive (`src/cognitive.rs`)

- **Source tag**: `"cognitive"`
- Monitors AI identity files (SOUL.md, AGENTS.md, etc.) for unauthorized changes
- Detects prompt injection and identity tampering

### policy (`src/policy.rs`)

- **Source tag**: `"policy"` (evaluated inline from auditd)
- User-defined YAML policy rules evaluated against audit events
- Config: `[policy]` section — `enabled`, `dir`

### admin (`src/admin.rs`)

- **Source tag**: `"admin"`
- Unix domain socket for authenticated admin commands
- Sends Info alerts on successful auth, Critical alerts on auth failures
- See [CLAWSUDO-AND-POLICY.md](CLAWSUDO-AND-POLICY.md#3-admin-key-system) for details

### barnacle (`src/barnacle.rs`)

- **Source tag**: `"barnacle"` (evaluated inline from auditd and sentinel)
- Vendor threat pattern database matching (injection, dangerous commands, privacy rules, supply-chain IOCs)
- Config: `[barnacle]` section — `enabled`, `vendor_dir`

### proxy (`src/proxy.rs`)

- **Source tag**: `"proxy"`
- API key vault proxy with DLP scanning on outbound LLM requests
- Sends alerts when DLP patterns match (credential leakage, PII)
- Config: `[proxy]` section — `enabled`, `bind`, `port`
- See [CLAWSUDO-AND-POLICY.md](CLAWSUDO-AND-POLICY.md#5-api-key-proxy) for details

### update (`src/update.rs`)

- **Source tag**: `"auto-update"`
- Auto-updater that checks for new GitHub releases on a configurable interval
- Sends alerts when updates are available or applied
- Config: `[auto_update]` section — `enabled`, `interval`

---

## Aggregator

The aggregator (`src/aggregator.rs`) sits between raw sources and consumers, preventing alert storms from overwhelming Slack or the TUI.

### What It Does

1. **Fuzzy Deduplication** — Replaces ASCII digits with `#` to create a "shape" key. Alerts with the same source + shape within the dedup window are suppressed.
   - `"Found 3 suspicious crontab entries for uid 1000"` and `"Found 4 suspicious crontab entries for uid 1000"` share the shape `"Found # suspicious crontab entries for uid ####"` → deduplicated.

2. **Per-Source Rate Limiting** — Each source is capped at N alerts per window. Excess alerts are dropped silently.

3. **Critical Bypass** — `Critical` alerts skip dedup and rate limiting, with only a very tight 5-second dedup window to prevent exact duplicates.

4. **Persistence** — Every alert that passes filtering is:
   - Appended to the **JSONL log** (`/var/log/clawtower/alerts.jsonl` or `/tmp/clawtower-<uid>/alerts.jsonl`)
   - Appended to the **audit chain** (hash-chained tamper-evident log)
   - Pushed to the **API alert store** (shared in-memory store for the HTTP API)

5. **Log Rotation** — Every 100 alerts, old dedup/rate-limit entries are cleaned up. JSONL log is rotated when it exceeds 10 MB.

> Note: `parity:behavior` mismatch diagnostics are deduplicated before entering the aggregator, reducing migration noise while preserving visibility.

### Configuration

```rust
pub struct AggregatorConfig {
    pub dedup_window: Duration,           // Default: 30 seconds
    pub scan_dedup_window: Duration,      // Default: 1 hour (for scan: sources)
    pub rate_limit_per_source: u32,       // Default: 20 alerts/source
    pub rate_limit_window: Duration,      // Default: 60 seconds
}
```

Currently uses `AggregatorConfig::default()` in `main.rs`. To tune, modify the defaults or pass a custom config.

### Severity-Gated Slack Forwarding

After aggregation, alerts are forwarded to `slack_tx` **only if** `alert.severity >= min_slack_severity`. This is configured via `min_slack_level` in the `[slack]` config section.

---

## Slack Integration

### Setup

1. Create a [Slack Incoming Webhook](https://api.slack.com/messaging/webhooks) for your workspace
2. Configure in `/etc/clawtower/config.toml`:

```toml
[slack]
enabled = true
webhook_url = "https://hooks.slack.com/services/T.../B.../xxx"
backup_webhook_url = ""   # Optional failover webhook
channel = "#security"
min_slack_level = "warning"   # Only send Warning+ to Slack
heartbeat_interval = 3600     # Heartbeat every hour (0 = disabled)
```

3. Or use the interactive wizard: `clawtower configure`
4. Or edit via the TUI Config tab (Tab → Config → slack section → Ctrl+S to save)

### Alert Formatting

Alerts are sent as Slack attachments with color-coded sidebars:

- **Green** (`#36a64f`): Info
- **Gold** (`#daa520`): Warning  
- **Red** (`#dc3545`): Critical

Each message includes:
- Title: `"{emoji} ClawTower Alert"`
- Text: The alert message
- Fields: Severity (short), Source (short)
- Timestamp: Alert creation time

### Failover

If the primary webhook fails, the notifier automatically tries `backup_webhook_url` (if configured).

### Startup & Heartbeat Messages

- **Startup**: `"🛡️ ClawTower watchdog started — independent monitoring active"` sent on boot
- **Heartbeat**: `"💚 ClawTower heartbeat — uptime: Xh Ym, alerts processed: N"` sent at `heartbeat_interval` seconds (0 disables)

---

## TUI Dashboard

The terminal dashboard (`src/tui.rs`) uses ratatui/crossterm and provides six tabs.

### Tabs

| # | Tab | Content |
|---|-----|---------|
| 0 | **Alerts** | Real-time feed of all alerts, newest first. Color-coded by severity (red=critical, yellow=warning, gray=info) |
| 1 | **Network** | Filtered view: only `source == "network"` alerts |
| 2 | **Falco** | Filtered view: only `source == "falco"` alerts |
| 3 | **FIM** | Filtered view: only `source == "samhain"` alerts |
| 4 | **System** | Status summary: ClawTower version, ACTIVE status, alert counts by severity |
| 5 | **Config** | Interactive config editor with section sidebar and field editing |

### Keyboard Shortcuts

| Key | Context | Action |
|-----|---------|--------|
| `Tab` / `Shift+Tab` | Global | Next/previous tab |
| `←` / `→` | Global (not in field editing) | Next/previous tab |
| `q` / `Esc` | Global (not editing) | Quit |
| `↑` / `↓` | Config sidebar | Navigate sections |
| `Enter` | Config sidebar | Enter fields panel |
| `↑` / `↓` | Config fields | Navigate fields |
| `Enter` | Config field (text/number) | Start editing |
| `Enter` | Config field (bool) | Toggle true/false |
| `Enter` | Config field (action) | Run action (e.g., install Falco) |
| `Esc` / `Backspace` | Config fields | Back to sidebar |
| `Enter` | Editing | Confirm edit |
| `Esc` | Editing | Cancel edit |
| `Ctrl+S` | Config tab | Save config (sudo popup if not root) |

### Config Editor

The Config tab provides a two-pane editor:
- **Left sidebar** (25%): Section list (general, slack, auditd, network, falco, samhain, api, scans, proxy, policy, barnacle, netpolicy)
- **Right panel** (75%): Fields for the selected section

Saving requires write access to the config file. If not running as root, a sudo password popup appears. The TUI writes directly to `config.toml` (it is no longer immutable). For persistent customizations that survive updates, use `config.d/` drop-in files instead — see [CONFIGURATION.md](CONFIGURATION.md#config-overrides-configd).

### Headless Mode

Run with `clawtower run --headless` to skip the TUI entirely. Alerts print to stderr. Useful for running as a systemd service.

---

## Tuning Alerts

### Reduce Noise

1. **Raise minimum alert level** — In `[general]`, set `min_alert_level = "warning"` to suppress Info-level alerts globally.

2. **Adjust Slack severity** — In `[slack]`, set `min_slack_level = "critical"` to only get Slack notifications for critical events. Options: `"info"`, `"warning"`, `"critical"`.

3. **Disable noisy sources** — Toggle individual monitors off:
   ```toml
   [network]
   enabled = false
   
   [falco]
   enabled = false
   ```

4. **Aggregator dedup windows** — The default 30-second dedup window suppresses repeated identical alerts. Scan-prefixed sources use a 1-hour window. To change, modify `AggregatorConfig::default()` in `src/aggregator.rs`.

5. **Rate limiting** — Default: 20 alerts per source per 60 seconds. Excess alerts from a single source are dropped. Critical alerts always pass through.

### Scan Interval

Periodic scanner frequency is set in `[scans]`:
```toml
[scans]
interval = 300   # seconds between scan cycles
```

Increase this to reduce scan-related alert volume.

### Heartbeat Frequency

```toml
[slack]
heartbeat_interval = 3600   # seconds (0 = disabled)
```

### Watch Scope

Narrow the audit scope to specific users:
```toml
[general]
watched_users = ["1001", "1002"]  # Numeric UIDs (find with: id -u deploy)
watch_all_users = false
```

Or broaden it:
```toml
[general]
watch_all_users = true
```

### Policy Rules

Custom YAML policies in `[policy].dir` let you define exactly which events generate alerts and at what severity. Use this for fine-grained control over what constitutes a warning vs. informational event.
