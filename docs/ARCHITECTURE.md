# Architecture

## Module Dependency Graph

```
main.rs
├── config.rs          (Config, all *Config structs)
├── alerts.rs          (Alert, Severity, AlertStore)
├── auditd.rs          (ParsedEvent, parse_to_event, tail functions)
│   ├── behavior.rs    (classify_behavior — uses ParsedEvent)
│   └── policy.rs      (PolicyEngine — uses ParsedEvent)
├── aggregator.rs      (dedup + rate limit, uses Alert, audit_chain, api store)
│   └── audit_chain.rs (AuditChain — SHA-256 hash chain)
├── api.rs             (HTTP server, AlertRingBuffer, SharedAlertStore)
├── slack.rs           (SlackNotifier — independent webhook)
├── tui.rs             (Ratatui dashboard — consumes Alert stream)
├── scanner.rs         (periodic security scans)
│   └── cognitive.rs   (AI identity file integrity — called by scanner)
├── sentinel.rs        (real-time file integrity via inotify)
├── barnacle.rs      (vendor threat pattern engine — regex DBs)
├── admin.rs           (Unix socket + Argon2 auth)
├── firewall.rs        (UFW state monitor)
├── logtamper.rs       (audit log tampering detection)
├── network.rs         (iptables log parser)
├── journald.rs        (journalctl -k tail, reuses network parser)
├── netpolicy.rs       (outbound connection allowlist/blocklist)
├── falco.rs           (Falco JSON log tail)
├── samhain.rs         (Samhain FIM log tail)
├── proxy.rs           (LLM API proxy with key mapping + DLP)
└── update.rs          (self-update from GitHub + Ed25519 verify)

bin/clawsudo.rs        (standalone binary, own policy loader)
src/preload/interpose.c  (standalone .so, no Rust dependency)
```

## Configuration Layering

ClawTower's configuration is assembled from multiple files, merged in a deterministic order.

### Config Loading

```
config.toml  →  config.d/*.toml (alphabetical)  →  merge_toml()  →  Config struct
```

1. **Base config** — `/etc/clawtower/config.toml` is loaded first
2. **Overlays** — all `*.toml` files in `/etc/clawtower/config.d/` are loaded in alphabetical order
3. **Merge** — each overlay is merged into the base via `merge_toml()`:
   - **Scalars** — overlay value replaces base value
   - **Lists** — use `_add` suffix to append items, `_remove` suffix to remove items (original key is untouched if neither is present)
   - **Tables** — merged recursively (nested keys are individually replaced/added)

**Config protection:** `config.toml` is owned `root:root 644`. Since ClawTower monitors a non-root agent, the agent cannot modify root-owned config files — file permissions are sufficient protection without `chattr +i`.

### Policy Loading

```
default.yaml  →  other *.yaml (alphabetical)  →  name-based merge  →  PolicyEngine
```

1. **Defaults** — `default.yaml` is loaded first, providing baseline rules
2. **User rules** — remaining `*.yaml` files are loaded alphabetically
3. **Merge** — rules are matched by name:
   - Same name → user rule **replaces** default rule entirely
   - `enabled: false` → disables a default rule by name
   - New names → added alongside defaults

---

## Data Flow — Alert Pipeline

```
                    ┌─────────────┐
                    │   auditd    │──→ parse_to_event() ──→ behavior.classify_behavior()
                    │  tail loop  │                    └──→ policy.evaluate()
                    └──────┬──────┘                    └──→ event_to_alert()
                           │
  ┌────────────┐    ┌──────▼──────┐    ┌──────────┐
  │  network   │──→ │             │    │          │
  │  sentinel  │──→ │   raw_tx    │──→ │ Aggreg.  │──→ alert_tx ──→ TUI
  │  falco     │──→ │  (channel)  │    │          │
  │  samhain   │──→ │             │    │  dedup   │──→ slack_tx ──→ Slack webhook
  │  firewall  │──→ │             │    │  rate    │
  │  logtamper │──→ │             │    │  limit   │──→ api_store (ring buffer)
  │  scanner   │──→ │             │    │          │
  │  admin     │──→ │             │    │          │
  │  proxy     │──→ │             │    │          │
  └────────────┘    └─────────────┘    │          │
                                       │  audit   │──→ audit.chain (append-only file)
                                       │  chain   │
                                       └──────────┘
```

**Three-stage channel pipeline** (all `mpsc::channel`):
1. **Sources → raw_tx/raw_rx** (capacity: 1000) — all sources push raw alerts
2. **Aggregator → alert_tx/alert_rx** (capacity: 1000) — filtered alerts to TUI
3. **Aggregator → slack_tx/slack_rx** (capacity: 100) — alerts meeting min severity to Slack

## Auditd Event Parsing

The auditd parser (`src/auditd.rs`) handles three record types:

1. **EXECVE records** — Contains `argc` and `a0..aN` fields. Args may be hex-encoded (e.g., `a0=2F7573722F62696E2F6375726C` → `/usr/bin/curl`). The parser decodes hex when all characters are hex digits and length is even.

2. **SYSCALL records** — Contains `syscall=<num>`, `success=yes|no`, `uid=<uid>`. Syscall numbers are mapped via a static lookup table for aarch64 (e.g., 221→execve, 56→openat, 203→connect). File paths extracted from `name=` or `exe=` fields.

3. **AVC/Anomaly records** — AppArmor denials (`apparmor="DENIED"`), anomaly events. Always classified as security events.

**User filtering:** SYSCALL records are filtered by `uid=` or `auid=` matching the configured watched user. EXECVE records pass through unfiltered (they follow an already-filtered SYSCALL record in auditd's output).

## Behavior Classification

The behavior engine (`src/behavior.rs`) applies hardcoded rules in priority order:

| Priority | Category | Severity | Triggers |
|----------|----------|----------|----------|
| 1 | SEC_TAMPER | Critical | `ufw disable`, `systemctl stop auditd`, LD_PRELOAD bypass, log clearing, binary replacement, history tampering (16+ patterns) |
| 2 | PRIV_ESC | Critical | Read `/etc/shadow`, write `/etc/passwd`, container escapes, SSH key injection, process injection |
| 3 | DATA_EXFIL | Critical | `curl`, `wget`, `nc`, `ncat`, `netcat`, `socat` to non-safe hosts; DNS tunneling; network tunnels; memory dumps |
| 4 | SIDE_CHAN | Critical/Warning | Cache attack tools (mastik, flush-reload, prime-probe, sgx-step); `perf_event_open` syscall |
| 5 | RECON | Warning | `whoami`, `id`, `uname`; reading `.env`, `.ssh/id_rsa`, `.aws/credentials`; DNS lookups |

Also checks syscall-level events: `openat` on sensitive paths, `unlinkat` on critical files, container escape via `/var/run/docker.sock`, suspicious temp file creation. Build-tool child processes (cargo, gcc, etc.) are allowlisted to reduce false positives.

### Shadow Parity Mode (Migration Bridge)

To support de-hardcoding migration, auditd can run the new detector abstraction path in parallel:

- Config: `[behavior].detector_shadow_mode = true`
- Legacy behavior classification remains the production decision path
- Adapter output is compared against legacy output for parity
- Mismatches emit deduped `parity:behavior` Info alerts for diagnostics

Parity counters are exposed by the API (`/api/status`, `/api/security`) as:

- `parity.mismatches_total`
- `parity.alerts_emitted`
- `parity.alerts_suppressed`

This enables a parity-first rollout without changing alerting semantics.

## Aggregator — Dedup and Rate Limiting

The aggregator (`src/aggregator.rs`) sits between all sources and all consumers.

**Deduplication:** Key = `"{source}:{fuzzy_message}"` where digits are replaced with `#`. If the same key appears within the dedup window, the duplicate is suppressed. Default windows: 30 seconds for normal sources, **1 hour** for `scan:`-prefixed sources.

**Rate limiting:** Per-source, max 20 alerts per 60-second sliding window. Tracked via a vector of timestamps, pruned on each check.

**Critical bypass:** Critical alerts have a tighter dedup window (5 seconds) but are never rate-limited.

**Cleanup:** Every 100 processed alerts, old dedup entries (>3× the larger dedup window) and empty rate limit buckets are pruned to prevent unbounded memory growth.

## Hash Chain Verification

Each audit entry in `/var/log/clawtower/audit.chain` is a JSON line:

```json
{
  "seq": 42,
  "ts": "2026-02-13T22:00:00Z",
  "severity": "warning",
  "source": "behavior",
  "message": "[BEHAVIOR:RECON] whoami",
  "prev_hash": "abc123...",
  "hash": "def456..."
}
```

**Hash computation:** `SHA-256("{seq}|{ts}|{severity}|{source}|{message}|{prev_hash}")`

**Genesis:** First entry uses `prev_hash = "0000...0000"` (64 zeros).

**Verification** (`clawtower verify-audit`): Reads every entry sequentially, verifies:
1. Sequence numbers are contiguous (1, 2, 3, ...)
2. Each entry's `prev_hash` matches the previous entry's `hash`
3. Each entry's `hash` matches the recomputed hash

Any tampering (modified message, deleted entry, reordered entries) breaks the chain.

**Resumption:** When restarting, `AuditChain::new()` reads the last entry to get `last_seq` and `last_hash`, then continues appending.

## Threat Model

| Layer | Defends Against | Mechanism |
|-------|----------------|-----------|
| **auditd** | Unlogged commands | Kernel-level logging, immutable rules (`-e 2`) |
| **behavior engine** | Known attack patterns | Hardcoded classification of exfil/privesc/recon/tamper |
| **policy engine** | Configurable threats | YAML rules with glob matching and whitelists |
| **clawsudo** | Unauthorized privilege use | Policy gate before `sudo`, fail-secure default |
| **LD_PRELOAD** | Syscall execution | Blocks calls at libc level *before* they happen |
| **sentinel** | Real-time file tampering | inotify + quarantine/restore + BarnacleDefense content scanning |
| **cognitive** | AI identity drift | SHA-256 baselines of SOUL.md, AGENTS.md, etc. |
| **aggregator** | Alert fatigue | Dedup + rate limiting without suppressing criticals |
| **audit chain** | Log tampering | SHA-256 hash chain, append-only |
| **Slack webhook** | Agent silencing alerts | Independent webhook, not routed through agent |
| **file permissions** | Config modification | Root-owned files (644) inaccessible to monitored agent |
| **AppArmor** | Agent accessing watchdog | MAC profile denying `openclaw` user access |
| **systemd hardening** | Service killing | `Restart=always`, `WatchdogSec=30`, sudoers deny |
| **DLP proxy** | Secret leakage via API | Regex scanning of outbound LLM requests |
| **admin key** | Unauthorized management | Argon2 auth, rate limiting, lockout |

## See Also

- [ALERT-PIPELINE.md](ALERT-PIPELINE.md) — Detailed alert model, aggregator tuning, Slack integration
- [SENTINEL.md](SENTINEL.md) — Real-time file integrity monitoring deep dive
- [MONITORING-SOURCES.md](MONITORING-SOURCES.md) — Every real-time data source in detail
- [SECURITY-SCANNERS.md](SECURITY-SCANNERS.md) — All 30+ periodic security scanners
- [CLAWSUDO-AND-POLICY.md](CLAWSUDO-AND-POLICY.md) — clawsudo, admin key, audit chain, proxy, LD_PRELOAD
