# ClawTower Configuration Reference

## Config Layering

ClawTower uses a layered configuration system. Upstream defaults ship in base files;
your customizations live in separate override files that are never touched by updates.

### File Layout

| File | Owner | Purpose |
|------|-------|---------|
| `/etc/clawtower/config.toml` | Upstream | Base config — replaced on updates |
| `/etc/clawtower/config.d/*.toml` | You | Your overrides — never touched by updates |
| `/etc/clawtower/policies/default.yaml` | Upstream | Base detection rules |
| `/etc/clawtower/policies/*.yaml` | You | Your custom/override rules |

### Config Overrides (config.d/)

Create `.toml` files in `/etc/clawtower/config.d/`. They're loaded alphabetically
after `config.toml` and merged:

- **Scalars** — your value replaces the default
- **Lists** — use `_add` to append, `_remove` to remove, or set the field directly to replace

#### Examples

Disable Falco and add a host to the network allowlist:

```toml
# /etc/clawtower/config.d/my-overrides.toml
[falco]
enabled = false

[netpolicy]
allowed_hosts_add = ["myapi.example.com"]
```

Remove a default allowlisted CIDR:

```toml
# /etc/clawtower/config.d/strict-network.toml
[network]
allowlisted_cidrs_remove = ["169.254.0.0/16"]
```

#### Naming Convention

Prefix with numbers to control load order: `00-first.toml`, `50-middle.toml`, `99-last.toml`.

### Policy Overrides

Create `.yaml` files in `/etc/clawtower/policies/`. Rules are merged by `name`:

- Same name as a default rule → **your version replaces it entirely**
- New name → added to the rule set
- `enabled: false` → disables a rule

```yaml
# /etc/clawtower/policies/custom.yaml
rules:
  # Override the exfil rule
  - name: "block-data-exfiltration"
    description: "Customized exfil detection"
    match:
      command: ["curl", "wget"]
      exclude_args:
        - "mycompany-api.com"
    action: critical

  # Disable a noisy rule
  - name: "detect-scheduled-tasks"
    enabled: false
```

> **Note:** When you override a rule by name, you own that rule. Future upstream
> improvements to that rule won't auto-merge — this is by design.

### Updates

When ClawTower updates, `config.toml` and `default.yaml` are replaced with new versions.
Your files in `config.d/` and custom policy YAMLs are untouched. You don't need to do anything.

---

ClawTower uses a **TOML** configuration file, typically located at `/etc/clawtower/config.toml`.

> ⚠️ **TOML only.** Despite the `config.example.yaml` file in the repo root, ClawTower's config parser only reads TOML format. The YAML file is a legacy reference and should not be used directly.

Most sections use `#[serde(default)]` — missing sections gracefully fall back to defaults. However, **five sections are required** and must be present in the config file: `[general]`, `[slack]`, `[auditd]`, `[network]`, and `[scans]`. All other sections (`[falco]`, `[samhain]`, `[api]`, `[proxy]`, `[policy]`, `[barnacle]`, `[netpolicy]`, `[ssh]`, `[sentinel]`, `[auto_update]`) are optional and have sensible defaults.

---

## Table of Contents

- [`[general]`](#general)
- [`[slack]`](#slack)
- [`[auditd]`](#auditd)
- [`[network]`](#network)
- [`[falco]`](#falco)
- [`[samhain]`](#samhain)
- [`[ssh]`](#ssh)
- [`[api]`](#api)
- [`[scans]`](#scans)
- [`[proxy]`](#proxy)
- [`[policy]`](#policy)
- [`[barnacle]`](#barnacle)
- [`[netpolicy]`](#netpolicy)
- [`[behavior]`](#behavior)
- [`[sentinel]`](#sentinel)
- [`[auto_update]`](#auto_update)

---

## `[general]` ⚠️ Required

**Struct:** `GeneralConfig`

Controls which users are monitored and the global alert threshold. This section **must** be present in the config file (no `#[serde(default)]`).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `watched_user` | `Option<String>` | `None` | Single UID to monitor (backward compat; prefer `watched_users`) |
| `watched_users` | `Vec<String>` | `[]` | List of **numeric UIDs** to monitor (e.g., `["1000"]`, not usernames — these match against auditd's `uid=` and `auid=` fields) |
| `watch_all_users` | `bool` | `false` | If `true`, monitor all users regardless of `watched_users` |
| `min_alert_level` | `String` | *(required)* | Minimum severity: `"info"`, `"warning"`, or `"critical"` |
| `log_file` | `String` | *(required)* | Path to ClawTower's own log file |

**User resolution logic** (`effective_watched_users()`):
- If `watch_all_users = true` → monitor everyone
- Otherwise merges `watched_user` + `watched_users` into a single list
- If resulting list is empty → monitor everyone

```toml
[general]
watched_users = ["1000"]   # Numeric UID, not username (find with: id -u openclaw)
watch_all_users = false
min_alert_level = "info"
log_file = "/var/log/clawtower/clawtower.log"
```

> ⚠️ **Common mistake:** Using usernames (e.g., `"openclaw"`) instead of numeric UIDs (e.g., `"1000"`). ClawTower matches against auditd's `uid=` and `auid=` fields, which are numeric. Find your user's UID with `id -u <username>`.

---

## `[slack]` ⚠️ Required

**Struct:** `SlackConfig`

Slack incoming webhook notifications with failover support. This section **must** be present in the config file.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `Option<bool>` | `None` | Explicitly enable/disable. `None` = enabled if `webhook_url` is set |
| `webhook_url` | `String` | *(required)* | Primary incoming webhook URL |
| `backup_webhook_url` | `String` | `""` | Failover webhook if primary fails |
| `channel` | `String` | *(required)* | Slack channel name (e.g., `"#security"`) |
| `min_slack_level` | `String` | *(required)* | Minimum severity to send to Slack |
| `heartbeat_interval` | `u64` | `3600` | Seconds between health heartbeats (0 = disabled) |

```toml
[slack]
enabled = true
webhook_url = "https://hooks.slack.com/services/T.../B.../xxx"
backup_webhook_url = ""
channel = "#security"
min_slack_level = "warning"
heartbeat_interval = 3600
```

---

## `[auditd]` ⚠️ Required

**Struct:** `AuditdConfig`

Linux audit log monitoring (syscall events). This section **must** be present in the config file.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | *(required)* | Enable auditd log tailing |
| `log_path` | `String` | *(required)* | Path to audit log (typically `/var/log/audit/audit.log`) |

```toml
[auditd]
enabled = true
log_path = "/var/log/audit/audit.log"
```

---

## `[network]` ⚠️ Required

**Struct:** `NetworkConfig`

Network/iptables log monitoring. This section **must** be present in the config file.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | *(required)* | Enable network log monitoring |
| `log_path` | `String` | *(required)* | Path to syslog (for file-based source) |
| `log_prefix` | `String` | *(required)* | Iptables log prefix to match (e.g., `"CLAWTOWER_NET"`) |
| `source` | `String` | `"auto"` | Log source: `"auto"`, `"journald"`, or `"file"` |
| `allowlisted_cidrs` | `Vec<String>` | RFC1918 + multicast + loopback | CIDR ranges to never alert on |
| `allowlisted_ports` | `Vec<u16>` | `[443, 53, 123, 5353]` | Ports to never alert on |

**Default CIDRs:** `192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`, `169.254.0.0/16`, `127.0.0.0/8`, `224.0.0.0/4`

```toml
[network]
enabled = true
log_path = "/var/log/syslog"
log_prefix = "CLAWTOWER_NET"
source = "auto"
allowlisted_cidrs = ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
allowlisted_ports = [443, 53, 123, 5353]
```

---

## `[falco]`

**Struct:** `FalcoConfig`

Falco eBPF syscall monitoring integration.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `false` | Enable Falco log tailing |
| `log_path` | `String` | `"/var/log/falco/falco_output.jsonl"` | Path to Falco JSON log |

```toml
[falco]
enabled = false
log_path = "/var/log/falco/falco_output.jsonl"
```

---

## `[samhain]`

**Struct:** `SamhainConfig`

Samhain file integrity monitoring integration.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `false` | Enable Samhain log tailing |
| `log_path` | `String` | `"/var/log/samhain/samhain.log"` | Path to Samhain log |

```toml
[samhain]
enabled = false
log_path = "/var/log/samhain/samhain.log"
```

---

## `[ssh]`

**Struct:** `SshConfig`

SSH login event monitoring via journald.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `true` | Enable SSH login monitoring |

```toml
[ssh]
enabled = true
```

---

## `[api]`

**Struct:** `ApiConfig`

HTTP REST API server for external integrations.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `false` | Enable the API server |
| `bind` | `String` | `"127.0.0.1"` | Bind address |
| `port` | `u16` | `18791` | Listen port |
| `auth_token` | `String` | `""` | Optional bearer token for API auth (`/api/health` always unauthenticated) |

**Endpoints:** `/api/status`, `/api/alerts`, `/api/health`, `/api/security`

```toml
[api]
enabled = false
bind = "127.0.0.1"
port = 18791
auth_token = ""
```

---

## `[scans]` ⚠️ Required

**Struct:** `ScansConfig`

Periodic security scanner configuration. This section **must** be present in the config file.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `interval` | `u64` | *(required)* | Seconds between scan cycles |
| `persistence_interval` | `u64` | `300` | Seconds between persistence-focused scan cycles |
| `dedup_interval_secs` | `u64` | `3600` | Seconds before repeating unchanged scanner findings |

```toml
[scans]
interval = 300
persistence_interval = 300
dedup_interval_secs = 3600
```

---

## `[proxy]`

**Struct:** `ProxyConfig`

API key vault proxy with DLP scanning.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `false` | Enable the proxy server |
| `bind` | `String` | `"127.0.0.1"` | Bind address |
| `port` | `u16` | `18790` | Listen port |
| `key_mapping` | `Vec<KeyMapping>` | `[]` | Virtual→real key mappings |
| `dlp` | `DlpConfig` | `{ patterns: [] }` | DLP scanning configuration |

### `[[proxy.key_mapping]]`

**Struct:** `KeyMapping`

| Field | Type | Description |
|-------|------|-------------|
| `virtual_key` | `String` | Virtual key the agent uses (alias: `virtual`) |
| `real` | `String` | Actual API key sent upstream |
| `provider` | `String` | `"anthropic"` (x-api-key) or `"openai"` (Bearer token) |
| `upstream` | `String` | Upstream API base URL |

### `[[proxy.dlp.patterns]]`

**Struct:** `DlpPattern`

| Field | Type | Description |
|-------|------|-------------|
| `name` | `String` | Pattern name for logging |
| `regex` | `String` | Regex pattern to match |
| `action` | `String` | `"block"` (reject request) or `"redact"` (replace with `[REDACTED]`) |

```toml
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

[[proxy.dlp.patterns]]
name = "credit-card"
regex = "\\b\\d{4}[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4}\\b"
action = "redact"

[[proxy.dlp.patterns]]
name = "aws-key"
regex = "AKIA[0-9A-Z]{16}"
action = "block"
```

---

## `[policy]`

**Struct:** `PolicyConfig`

YAML policy engine for detection rules (distinct from clawsudo enforcement).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `true` | Enable policy evaluation |
| `dir` | `String` | `"./policies"` | Directory containing `.yaml`/`.yml` policy files |

Files named `clawsudo*.yaml` are automatically skipped in the detection pipeline.

```toml
[policy]
enabled = true
dir = "./policies"
```

---

## `[barnacle]`

**Struct:** `BarnacleDefenseConfig`

Vendor threat pattern engine loading JSON databases.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `false` | Enable BarnacleDefense pattern matching |
| `vendor_dir` | `String` | `"./vendor/barnacle/barnacle/skill/configs"` | Path to vendor JSON pattern files |

**Expected files in `vendor_dir`:**
- `injection-patterns.json`
- `dangerous-commands.json`
- `privacy-rules.json`
- `supply-chain-ioc.json`

```toml
[barnacle]
enabled = false
vendor_dir = "./vendor/barnacle/barnacle/skill/configs"
```

---

## `[netpolicy]`

**Struct:** `NetPolicyConfig`

Network policy enforcement (allowlist/blocklist).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `false` | Enable network policy |
| `mode` | `String` | `"blocklist"` | `"allowlist"` (deny all except listed) or `"blocklist"` (allow all except listed) |
| `allowed_hosts` | `Vec<String>` | `[]` | Hosts allowed in allowlist mode (supports `*.suffix` wildcards) |
| `allowed_ports` | `Vec<u16>` | `[80, 443, 53]` | Ports allowed in allowlist mode |
| `blocked_hosts` | `Vec<String>` | `[]` | Hosts blocked in blocklist mode (supports `*.suffix` wildcards) |

```toml
[netpolicy]
enabled = false
mode = "blocklist"
allowed_hosts = ["api.anthropic.com", "*.openai.com", "github.com"]
allowed_ports = [80, 443, 53]
blocked_hosts = ["evil.com", "*.malware.net"]
```

---

## `[behavior]`

**Struct:** `BehaviorConfig`

Hardcoded behavior detector tuning and migration controls.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `safe_hosts` | `Vec<String>` | `[]` | Extra allowlisted hosts for behavior exfil checks |
| `detector_shadow_mode` | `bool` | `false` | Run abstraction detector in shadow mode and emit parity diagnostics on mismatch |

When `detector_shadow_mode = true`, ClawTower keeps production behavior alerts unchanged,
but also runs the new detector abstraction path in parallel and compares outputs.
Mismatches emit `parity:behavior` Info alerts (deduped) and parity counters are exposed in:

- `GET /api/status` → `parity.*`
- `GET /api/security` → `parity.*`

```toml
[behavior]
safe_hosts = ["internal-api.example.com"]
detector_shadow_mode = false
```

---

## `[sentinel]`

**Struct:** `SentinelConfig`

Real-time file integrity monitoring via inotify.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `true` | Enable sentinel file watching |
| `watch_paths` | `Vec<WatchPathConfig>` | 3 default paths (see below) | Paths to monitor |
| `quarantine_dir` | `String` | `"/etc/clawtower/quarantine"` | Where quarantined files are stored |
| `shadow_dir` | `String` | `"/etc/clawtower/sentinel-shadow"` | Where shadow copies are stored |
| `debounce_ms` | `u64` | `200` | Milliseconds to debounce filesystem events |
| `scan_content` | `bool` | `true` | Run BarnacleDefense pattern scan on changed file contents |
| `max_file_size_kb` | `u64` | `1024` | Maximum file size (KB) for content scanning |

### `[[sentinel.watch_paths]]`

**Struct:** `WatchPathConfig`

| Field | Type | Description |
|-------|------|-------------|
| `path` | `String` | Absolute path to the file or directory to watch |
| `patterns` | `Vec<String>` | Glob patterns for matching (e.g., `["*"]` for all) |
| `policy` | `WatchPolicy` | `"protected"` or `"watched"` |

**Policies:**
- **`protected`**: On change → quarantine current file, restore from shadow copy, send Critical alert
- **`watched`**: On change → update shadow copy, send Info alert with diff

**Default watch paths:**
1. `SOUL.md` → protected
2. `AGENTS.md` → protected
3. `MEMORY.md` → protected

Additional defaults include identity/control files (e.g. `IDENTITY.md`, `USER.md`),
watch-only files (e.g. `HEARTBEAT.md`, `TOOLS.md`), OpenClaw credentials/config
paths, persistence-sensitive shell/profile files, and selected system/user startup
locations.

```toml
[sentinel]
enabled = true
quarantine_dir = "/etc/clawtower/quarantine"
shadow_dir = "/etc/clawtower/sentinel-shadow"
debounce_ms = 200
scan_content = true
max_file_size_kb = 1024

[[sentinel.watch_paths]]
path = "/home/openclaw/.openclaw/workspace/SOUL.md"
patterns = ["*"]
policy = "protected"

[[sentinel.watch_paths]]
path = "/home/openclaw/.openclaw/workspace/AGENTS.md"
patterns = ["*"]
policy = "protected"

[[sentinel.watch_paths]]
path = "/home/openclaw/.openclaw/workspace/MEMORY.md"
patterns = ["*"]
policy = "protected"

[[sentinel.watch_paths]]
path = "/home/openclaw/.openclaw/workspace/HEARTBEAT.md"
patterns = ["*"]
policy = "watched"
```

---

## `[auto_update]`

**Struct:** `AutoUpdateConfig`

Background auto-updater checking GitHub releases.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `true` | Enable automatic update checks |
| `interval` | `u64` | `300` | Seconds between update checks |

The auto-updater downloads new binaries with SHA-256 checksum verification (required) and Ed25519 signature verification (if `.sig` asset exists). Performs the `chattr -i` → replace → `chattr +i` → restart dance.

```toml
[auto_update]
enabled = true
interval = 300
```

---

## See Also

- [SENTINEL.md](SENTINEL.md) — Deep dive into `[sentinel]` configuration and behavior
- [ALERT-PIPELINE.md](ALERT-PIPELINE.md) — How `min_alert_level` and `min_slack_level` affect alert routing
- [POLICIES.md](POLICIES.md) — YAML policy format for `[policy]` directory
- [SECURITY-SCANNERS.md](SECURITY-SCANNERS.md) — What the `[scans]` interval controls
- [CLAWSUDO-AND-POLICY.md](CLAWSUDO-AND-POLICY.md) — `[proxy]` DLP configuration and admin key details
- [INSTALL.md](INSTALL.md) — Installation steps that create the default config

---

## Complete Example

A fully-commented config with every field and section documented:

```toml
# ═══════════════════════════════════════════════════════════════════════
# ClawTower Configuration — /etc/clawtower/config.toml
# All sections use serde(default) — missing fields use sensible defaults
# ═══════════════════════════════════════════════════════════════════════

[general]
# Users to monitor by UID string. Find your UID with: id -u openclaw
# Empty list + watch_all_users=false means watch ALL users.
watched_users = ["1000"]
# Backward-compat single user (merged into watched_users internally):
# watched_user = "1000"
# Override: monitor every user regardless of watched_users list
watch_all_users = false
# Minimum severity for internal alert processing: "info", "warning", "critical"
min_alert_level = "info"
# ClawTower's own log file
log_file = "/var/log/clawtower/clawtower.log"

[slack]
# Explicitly enable/disable (nil = enabled if webhook_url is non-empty)
enabled = true
# Primary Slack incoming webhook URL
webhook_url = "https://hooks.slack.com/services/T.../B.../xxx"
# Failover webhook URL (empty = disabled)
backup_webhook_url = ""
# Target Slack channel
channel = "#security"
# Minimum severity forwarded to Slack: "info", "warning", "critical"
min_slack_level = "warning"
# Seconds between health heartbeat messages (0 = disabled)
heartbeat_interval = 3600

[auditd]
# Enable tailing /var/log/audit/audit.log for syscall/exec events
enabled = true
log_path = "/var/log/audit/audit.log"

[network]
# Enable iptables/netfilter log monitoring
enabled = true
# Syslog path (used when source = "file")
log_path = "/var/log/syslog"
# Must match your iptables rule: -j LOG --log-prefix "CLAWTOWER_NET"
log_prefix = "CLAWTOWER_NET"
# "auto" = prefer journald, fallback to file; "journald"; "file"
source = "auto"
# CIDR ranges that never generate alerts
allowlisted_cidrs = [
    "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12",
    "169.254.0.0/16", "127.0.0.0/8", "224.0.0.0/4",
]
# Destination ports that never generate alerts
allowlisted_ports = [443, 53, 123, 5353]

[falco]
# Falco eBPF integration (requires Falco installed separately)
enabled = false
log_path = "/var/log/falco/falco_output.jsonl"

[samhain]
# Samhain FIM integration (requires Samhain installed separately)
enabled = false
log_path = "/var/log/samhain/samhain.log"

[ssh]
# Monitor SSH login events via journald (Accepted/Failed/Invalid user)
enabled = true

[api]
# HTTP REST API: /api/status, /api/alerts, /api/health, /api/security
enabled = false
# Use 127.0.0.1 for local-only; 0.0.0.0 for network access
bind = "127.0.0.1"
port = 18791
# Optional bearer token; empty disables API auth
auth_token = ""

[scans]
# Seconds between periodic security scan cycles (30+ checks)
interval = 300
# Seconds between persistence-focused scans
persistence_interval = 300
# Repeat unchanged scanner findings at most once per this interval
dedup_interval_secs = 3600

[proxy]
# API key vault proxy with DLP scanning
enabled = false
bind = "127.0.0.1"
port = 18790

# Virtual-to-real key mapping (agent never sees real keys):
# [[proxy.key_mapping]]
# virtual_key = "vk-anthropic-001"     # Key the agent uses
# real = "sk-ant-api03-REAL-KEY"       # Actual key sent upstream
# provider = "anthropic"                # "anthropic" (x-api-key) or "openai" (Bearer)
# upstream = "https://api.anthropic.com"

# DLP patterns scan request bodies for sensitive data:
# [[proxy.dlp.patterns]]
# name = "ssn"
# regex = "\\b\\d{3}-\\d{2}-\\d{4}\\b"
# action = "block"                      # "block" (reject) or "redact" (replace)

[policy]
# YAML-based detection policy engine (clawsudo*.yaml files are skipped)
enabled = true
dir = "./policies"

[barnacle]
# BarnacleDefense vendor threat pattern matching (4 JSON databases)
enabled = false
vendor_dir = "./vendor/barnacle/barnacle/skill/configs"

[netpolicy]
# Network policy enforcement for outbound connections
enabled = false
# "allowlist" = deny-all-except; "blocklist" = allow-all-except
mode = "blocklist"
# Used in allowlist mode (supports *.suffix wildcards)
allowed_hosts = ["api.anthropic.com", "*.openai.com", "github.com"]
allowed_ports = [80, 443, 53]
# Used in blocklist mode
blocked_hosts = []

[behavior]
# Extra safe hosts for behavior exfil checks
safe_hosts = ["internal-api.example.com"]
# Run detector abstraction in shadow mode and emit parity diagnostics on mismatch
detector_shadow_mode = false

[sentinel]
# Real-time file integrity monitoring via inotify
enabled = true
quarantine_dir = "/etc/clawtower/quarantine"
shadow_dir = "/etc/clawtower/sentinel-shadow"
# Debounce window for filesystem events (ms)
debounce_ms = 200
# Run BarnacleDefense patterns on changed content
scan_content = true
# Skip files larger than this (KB)
max_file_size_kb = 1024

# "protected" = quarantine + restore on change → Critical alert
[[sentinel.watch_paths]]
path = "/home/openclaw/.openclaw/workspace/SOUL.md"
patterns = ["*"]
policy = "protected"

[[sentinel.watch_paths]]
path = "/home/openclaw/.openclaw/workspace/AGENTS.md"
patterns = ["*"]
policy = "protected"

# "watched" = update shadow, track diffs → Info alert
[[sentinel.watch_paths]]
path = "/home/openclaw/.openclaw/workspace/MEMORY.md"
patterns = ["*"]
policy = "protected"

# Example of a watched file (changes tracked, not auto-restored)
[[sentinel.watch_paths]]
path = "/home/openclaw/.openclaw/workspace/HEARTBEAT.md"
patterns = ["*"]
policy = "watched"

[auto_update]
# Check GitHub releases for updates (SHA-256 + optional Ed25519 verification)
enabled = true
# Seconds between update checks
interval = 300
```

## See Also

- [INSTALL.md](INSTALL.md) — Installation walkthrough and hardening steps
- [SENTINEL.md](SENTINEL.md) — Deep dive into `[sentinel]` file watching behavior
- [POLICIES.md](POLICIES.md) — Writing YAML rules for the `[policy]` engine
- [CLAWSUDO-AND-POLICY.md](CLAWSUDO-AND-POLICY.md) — `[proxy]` DLP setup and admin key system
- [TUNING.md](TUNING.md) — Production tuning including behavior parity shadow mode
- [INDEX.md](INDEX.md) — Full documentation index
