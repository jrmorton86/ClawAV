# ClawTower Monitoring Sources Reference

ClawTower monitors Linux systems through nine real-time data sources, each implemented as an async task that feeds alerts into a unified channel. This document covers every source, how it works internally, and how to add new ones.

---

## Table of Contents

1. [Auditd Integration](#1-auditd-integration)
2. [Behavioral Analysis](#2-behavioral-analysis)
3. [Network Monitoring](#3-network-monitoring)
4. [Firewall Monitoring](#4-firewall-monitoring)
5. [Journald (SSH & Kernel)](#5-journald-ssh--kernel)
6. [Log Tamper Detection](#6-log-tamper-detection)
7. [Falco Integration](#7-falco-integration)
8. [Samhain Integration](#8-samhain-integration)
9. [Network Policy](#9-network-policy)
10. [How to Add a New Monitoring Source](#10-how-to-add-a-new-monitoring-source)

---

## 1. Auditd Integration

**File:** `src/auditd.rs`

The auditd module is ClawTower's primary event source. It tails `/var/log/audit/audit.log` and parses raw audit records into structured events.

### Event Parsing

Three record types are parsed:

| Record Type | What's Extracted |
|---|---|
| `type=SYSCALL` | Syscall number → name (aarch64 mapping), success/fail, file path, UID/AUID, parent process exe |
| `type=EXECVE` | Command reconstruction from `a0`, `a1`, … fields; hex-encoded argument decoding |
| `type=AVC` / `ANOM` | Security denial events (AppArmor, SELinux, anomalies) |

Key helper: `extract_field(line, "key")` splits on whitespace and finds `key=value` tokens.

### The `ParsedEvent` Struct

Every parsed audit line becomes a `ParsedEvent`:

```rust
pub struct ParsedEvent {
    pub syscall_name: String,      // "execve", "openat", etc.
    pub command: Option<String>,   // Full reconstructed command (EXECVE only)
    pub args: Vec<String>,         // Individual arguments
    pub file_path: Option<String>, // From name= or exe= fields
    pub success: bool,
    pub raw: String,               // Original log line
    pub actor: Actor,              // Agent, Human, or Unknown
    pub ppid_exe: Option<String>,  // Parent process path (from /proc/<ppid>/exe)
}
```

### The Actor System

ClawTower attributes every event to an actor based on the `auid` (audit UID) field:

- **`Actor::Agent`** — `auid=4294967295` (unset) or missing. The process was spawned by a service/daemon, not an interactive login.
- **`Actor::Human`** — Any other `auid` value. A real user logged in and triggered this action.
- **`Actor::Unknown`** — EXECVE records (which don't carry their own auid) or AVC events.

Alerts are prefixed with `[AGENT]` or `[HUMAN]` tags for quick triage.

### User Filtering

The `watched_users` parameter limits parsing to specific UIDs. Events from other UIDs are silently dropped — **except** tamper-detection events (`key="clawtower-tamper"` or `key="clawtower-config"`), which always pass through regardless of user filter.

### Tamper Detection Keys

ClawTower installs auditd watch rules with special keys:

- **`clawtower-tamper`** — Fires on `chattr` execution (immutable flag removal attempts). Severity: Critical.
- **`clawtower-config`** — Fires on writes/attribute changes to protected ClawTower files. Severity: Critical.

### `connect()` Syscall Monitoring *(v0.3.3+)*

In addition to EXECVE-based command monitoring, ClawTower now monitors `connect()` syscalls (aarch64 syscall 203) via auditd rules for watched users. This catches outbound network connections at the syscall level, including:

- Direct socket connections that bypass shell-level detection (e.g., `python socket.connect()`)
- Connections made by compiled binaries without shell command lines
- Network activity from processes that don't appear in EXECVE records

The `connect()` events are parsed as SYSCALL records with destination address extracted from the audit fields, then fed through behavior classification for exfiltration detection. This complements iptables log monitoring by providing attribution (which user/process initiated the connection).

### Main Entry Point

`tail_audit_log_with_behavior_and_policy()` is the primary function (see also [ALERT-PIPELINE.md](ALERT-PIPELINE.md#alert-sources) for how alerts flow downstream). It:

1. Seeks to the end of the audit log
2. Polls for new lines every 500ms
3. For each line, runs the event through (in order):
   - **Tamper detection** (`check_tamper_event`)
   - **Policy engine** (user-configurable rules)
   - **SecureClaw pattern matching** (`check_command`) — see [SECURITY-SCANNERS.md](SECURITY-SCANNERS.md#secureclaw-pattern-engine)
   - **Behavior detection** (hardcoded rules — see §2)
   - **Base alert generation** (`event_to_alert`)

### Syscall Mapping

Syscall numbers are mapped for aarch64 via `syscall_name_aarch64()`. Key mappings include: `221=execve`, `56=openat`, `203=connect`, `35=unlinkat`, `198=socket`.

---

## 2. Behavioral Analysis

**File:** `src/behavior.rs`

The behavior engine classifies `ParsedEvent`s against ~200 static patterns organized into five threat categories (MITRE ATT&CK inspired):

| Category | Tag | Examples |
|---|---|---|
| **Data Exfiltration** | `DATA_EXFIL` | curl/wget/nc to unknown hosts, DNS tunneling, archive creation, credential theft |
| **Privilege Escalation** | `PRIV_ESC` | Reading `/etc/shadow`, writing `/etc/passwd`, container escapes, SSH key injection |
| **Security Tamper** | `SEC_TAMPER` | Disabling firewalls/auditd/AppArmor, log clearing, binary replacement, history wiping |
| **Reconnaissance** | `RECON` | `whoami`, `id`, `uname`, reading `.env`/`.ssh` files, DNS lookups |
| **Side Channel** | `SIDE_CHAN` | Cache attack tools (mastik, flush-reload, prime-probe), `perf_event_open` syscall |

### How Classification Works

`classify_behavior(event)` returns `Option<(BehaviorCategory, Severity)>`. It checks:

1. **EXECVE commands** (if `event.command` is present):
   - Extracts the binary basename from the first argument
   - Matches against pattern lists in priority order (Critical → Warning → Info)
   - Checks arguments for sensitive file paths, encoded data, suspicious flags

2. **Syscall-level events** (file path based):
   - `openat`/`statx` on critical paths → escalation or recon
   - `unlinkat`/`renameat` on system files → tampering
   - Container escape via `/var/run/docker.sock`, `/proc/1/root`

### Key Detection Patterns

**Network exfiltration:** `curl`, `wget`, `nc`, `ncat`, `netcat`, `socat` to any host not in the safe-host list (`api.anthropic.com`, `github.com`, `hooks.slack.com`, etc.).

**DNS tunneling:** `dig`, `nslookup`, `host` with long subdomain labels (>25 chars), many dots (>6), or shell substitution characters.

**LD_PRELOAD bypass:** Direct dynamic linker invocation, `LD_PRELOAD` environment variable setting, or static compilation with `musl-gcc`. Build-tool child processes (cargo, gcc, etc.) are allowlisted via `BUILD_TOOL_BASES` and `ppid_exe` checking.

**Persistence:** `crontab` (except `-l` listing), `at`, `systemctl enable`, writes to `/etc/cron*`, `/etc/systemd/system/`, `/etc/init.d/`.

### False Positive Reduction

- **Safe hosts list** for network tools (Anthropic, GitHub, Slack, npm, etc.)
- **Recon allowlist** for normal `ip neigh`/`ip addr`/`ip route` commands
- **Build tool suppression** — compiler/linker processes whose parent is cargo/gcc/make are not flagged for LD_PRELOAD patterns
- **`crontab -l`** is explicitly excluded from persistence detection

---

## 3. Network Monitoring

**File:** `src/network.rs`

Parses iptables/netfilter log lines from syslog or kernel messages.

### How It Works

1. Scans each log line for a configurable prefix string (e.g., `"CLAWTOWER_NET"`)
2. Extracts `SRC`, `DST`, `DPT`, and `PROTO` fields from iptables log format
3. Classifies traffic using `NetworkAllowlist`

### NetworkAllowlist

A CIDR + port allowlist determines whether traffic is known-good:

```rust
pub struct NetworkAllowlist {
    cidrs: Vec<IpNet>,   // e.g., 192.168.0.0/16, 10.0.0.0/8
    ports: Vec<u16>,     // e.g., 443, 53, 123, 5353
}
```

- **Allowed by CIDR:** RFC1918 ranges, link-local (169.254.0.0/16), loopback, multicast (224.0.0.0/4)
- **Allowed by port:** 443 (HTTPS), 53 (DNS), 123 (NTP), 5353 (mDNS)
- Traffic matching the allowlist → `Severity::Info`
- Everything else → `Severity::Warning`

### Tailing

`tail_network_log()` seeks to end-of-file and polls every 500ms for new lines. The journald integration (§5) provides an alternative input path for the same parser.

---

## 4. Firewall Monitoring

**File:** `src/firewall.rs`

Monitors UFW firewall state via polling.

### Mechanism

1. **Baseline capture** — Runs `ufw status verbose` at startup (falls back to `sudo ufw` if needed)
2. **Polling** — Re-checks every 30 seconds
3. **Change detection** — Simple line-by-line diff between baseline and current state

### Alert Conditions

| Condition | Severity |
|---|---|
| Firewall inactive on startup | Critical |
| Firewall disabled after startup | Critical (with diff) |
| Any rule change | Critical (with diff) |
| Firewall active, no changes | Info (startup only) |

The diff output shows `- removed` and `+ added` lines for quick diagnosis.

---

## 5. Journald (SSH & Kernel)

**File:** `src/journald.rs`

Two async functions that spawn `journalctl` child processes:

### `tail_journald_network`

Spawns `journalctl -k -f -o json --since now` (kernel messages in JSON format). Parses the `MESSAGE` field from each JSON line and passes it to `parse_iptables_line()` from the network module. This is the preferred path when journald is available — it replaces raw syslog file tailing.

### `tail_journald_ssh`

Spawns `journalctl -u ssh -u sshd -f -o cat --since now` and classifies SSH events. This is spawned as a separate task when `[ssh].enabled = true` in the config.

**Source tag:** `"ssh"`

| Log Content | Severity | Alert Tag |
|---|---|---|
| `Accepted` | Info | `SSH login:` |
| `Failed password` / `Failed publickey` | Warning | `SSH failed login:` |
| `Invalid user` | Warning | `SSH invalid user:` |

### Availability Check

`journald_available()` runs `journalctl --version` to test if systemd journal is present. The main daemon uses this to choose between journald and file-based monitoring.

---

## 6. Log Tamper Detection

**File:** `src/logtamper.rs`

Monitors the audit log file itself for evidence destruction.

### Three Detection Signals

| Signal | How Detected | Severity |
|---|---|---|
| **Missing** | `std::fs::metadata()` fails (not permission denied) | Critical |
| **Replaced** | Inode number changed between checks | Critical |
| **Truncated** | File size decreased between checks | Critical |

### Log Rotation Awareness

When an inode change is detected, ClawTower calls `crate::sentinel::is_log_rotation()` to check if a rotated copy exists (e.g., `audit.log.1`). If so, the event is downgraded to `Severity::Info` with source `logtamper/rotation`.

### Polling

`monitor_log_integrity()` runs in a loop with a configurable interval. In `main.rs`, the interval is set to **30 seconds**. It tracks `last_size` and `last_inode` across iterations. The first check establishes baseline values (no alert generated).

### Scanner Integration

`scan_audit_log_health()` provides a one-shot health check:
- Verifies the file exists and is accessible
- Checks permissions (world-writable = Fail, world-readable = Warn)
- Reports file size and mode

---

## 7. Falco Integration

**File:** `src/falco.rs`

Consumes alerts from [Falco](https://falco.org/), an eBPF-based runtime security tool.

### How It Works

1. Waits for the Falco JSON log file to appear (polls every 30 seconds)
2. Seeks to end-of-file and tails new entries
3. Parses each line as JSON, extracting `priority`, `output`, and `rule` fields

### Priority Mapping

| Falco Priority | ClawTower Severity |
|---|---|
| EMERGENCY, ALERT, CRITICAL | Critical |
| ERROR, WARNING | Warning |
| Everything else | Info |

### Alert Format

```
[RuleName] Falco output message
```

Falco is **optional** — if it's not installed, ClawTower simply logs "Waiting for Falco log" periodically and continues operating with its other detection layers.

---

## 8. Samhain Integration

**File:** `src/samhain.rs`

Consumes alerts from [Samhain](https://www.la-samhna.de/samhain/), a file integrity monitoring (FIM) tool.

### How It Works

1. Waits for the Samhain log file to appear (polls every 60 seconds)
2. Seeks to end-of-file and tails new entries
3. Parses severity from line prefixes and extracts the message after the timestamp bracket

### Severity Mapping

| Samhain Prefix | ClawTower Severity |
|---|---|
| `CRIT`, `ALERT` | Critical |
| `WARN` | Warning |
| `NOTICE`, `INFO`, `MARK` | Info |

### What Samhain Detects

Samhain monitors file checksums, mtimes, permissions, and ownership. Typical alerts include:
- Checksum mismatches on system binaries or config files
- Policy changes to `/etc/sudoers`, `/etc/shadow`
- Unexpected file modifications

Like Falco, Samhain is **optional** — ClawTower operates without it but gains deeper file integrity coverage when it's present.

---

## 9. Network Policy

**File:** `src/netpolicy.rs`

A policy engine for outbound connection control, operating at a higher level than the network allowlist.

### Two Modes

**Allowlist mode** (recommended for high-security): Only connections to explicitly listed hosts are permitted. Everything else generates a Critical alert.

**Blocklist mode**: All connections are permitted except those to explicitly blocked hosts.

### Configuration

```rust
NetPolicyConfig {
    enabled: bool,
    allowed_hosts: Vec<String>,  // e.g., ["api.anthropic.com", "*.openai.com"]
    allowed_ports: Vec<u16>,
    blocked_hosts: Vec<String>,  // e.g., ["evil.com", "*.malware.net"]
    mode: String,                // "allowlist" or "blocklist"
}
```

### Wildcard Matching

Hosts prefixed with `*.` match any subdomain: `*.openai.com` matches `api.openai.com`, `chat.openai.com`, etc.

### Command Scanning

`check_command(cmd)` extracts URLs from command strings (splitting on whitespace, parsing `http://` and `https://` prefixes), resolves the hostname and port, and validates each against the policy. Returns a `Vec<Alert>` — one for each blocked URL found. The `extract_host_from_url()` helper handles `user@host` patterns and strips quotes.

---

## 10. How to Add a New Monitoring Source

### Step 1: Create the Module

Create `src/mymonitor.rs`:

```rust
//! Description of what this monitors.

use anyhow::Result;
use tokio::sync::mpsc;
use crate::alerts::{Alert, Severity};

/// Parse a single line/event into an Alert
pub fn parse_line(line: &str) -> Option<Alert> {
    // Your parsing logic here
    Some(Alert::new(Severity::Info, "mymonitor", &format!("Event: {}", line)))
}

/// Async tail function — the main entry point
pub async fn tail_my_source(
    tx: mpsc::Sender<Alert>,
) -> Result<()> {
    // Option A: Tail a file (see auditd.rs, falco.rs, samhain.rs)
    // Option B: Spawn a child process (see journald.rs)
    // Option C: Poll a command (see firewall.rs)
    loop {
        // Read events, parse them, send alerts:
        // let _ = tx.send(alert).await;
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}
```

### Step 2: Register the Module

In `src/main.rs`, add:

```rust
pub mod mymonitor;
```

### Step 3: Spawn the Task

In your daemon's startup code (where other monitors are spawned), add:

```rust
let tx_clone = tx.clone();
tokio::spawn(async move {
    if let Err(e) = crate::mymonitor::tail_my_source(tx_clone).await {
        eprintln!("mymonitor failed: {}", e);
    }
});
```

### Step 4: Choose a Source Tag

The `source` field in `Alert::new(severity, "source", message)` is used for filtering and routing. Pick a unique, lowercase tag (e.g., `"mymonitor"`).

### Step 5: Add Tests

Follow the existing pattern — unit tests for parsing functions, using synthetic input:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_known_event() {
        let alert = parse_line("some known input").unwrap();
        assert_eq!(alert.severity, Severity::Warning);
        assert!(alert.message.contains("expected text"));
    }

    #[test]
    fn test_ignore_irrelevant() {
        assert!(parse_line("garbage").is_none());
    }
}
```

### Architecture Notes

- All monitors communicate through `mpsc::Sender<Alert>` — they are fully decoupled from alert routing/delivery.
- Use `Seek::SeekFrom::End(0)` when tailing files to skip historical data.
- For optional tools (like Falco/Samhain), wait for the log file to appear rather than failing.
- Poll intervals: 500ms for high-frequency sources (auditd, network), 2-30s for low-frequency (samhain, firewall).

## See Also

- [ALERT-PIPELINE.md](ALERT-PIPELINE.md) — How alerts from these sources flow through the aggregator
- [ARCHITECTURE.md](ARCHITECTURE.md) — Module dependency graph and data flow diagrams
- [SECURITY-SCANNERS.md](SECURITY-SCANNERS.md) — Periodic scanners (complementary to real-time sources)
- [SENTINEL.md](SENTINEL.md) — Deep dive into the Sentinel file integrity source
- [CONFIGURATION.md](CONFIGURATION.md) — Config sections that enable/disable each source
