# ClawSudo & Policy Engine Guide

ClawAV's security enforcement layer: a sudo gatekeeper, YAML policy engine, admin key system, tamper-evident audit chain, API key proxy with DLP, and LD_PRELOAD syscall guard.

---

## Table of Contents

1. [clawsudo — Sudo Proxy/Gatekeeper](#1-clawsudo--sudo-proxygatekeeper)
2. [Policy Engine](#2-policy-engine)
3. [Admin Key System](#3-admin-key-system)
4. [Audit Chain](#4-audit-chain)
5. [API Key Proxy](#5-api-key-proxy)
6. [LD_PRELOAD Guard](#6-ld_preload-guard)
7. [Examples](#7-examples)

---

## 1. clawsudo — Sudo Proxy/Gatekeeper

### What It Is

`clawsudo` is a drop-in replacement for `sudo` that evaluates every privileged command against a YAML policy before execution. It sits between the AI agent and the real `sudo` binary, acting as a gatekeeper.

```
Agent → clawsudo <command> → Policy Check → sudo <command> (or deny)
```

### How It Works

1. **Parse command** — extracts the binary name (basename) and full command string from arguments
2. **Load policies** — reads all `.yaml`/`.yml` files from `/etc/clawav/policies/` and `./policies/`
3. **Fail-secure** — if no policy files are found, **all commands are denied** (exit code 77)
4. **Evaluate** — first matching rule wins; rules are checked in file order
5. **Enforce** — based on the matched rule's `enforcement` field. If `enforcement` is not set, it's inferred from the `action` field: `critical`/`block` → deny, anything else → ask.

### Enforcement Actions

| Enforcement | Behavior | Exit Code |
|---|---|---|
| `allow` | Execute via `sudo` immediately | 0 (or command's exit code) |
| `deny` | Block execution, log, alert via Slack | 77 |
| `ask` | Wait for human approval (5-minute timeout) | 0 if approved, 78 if timeout |
| *(no match)* | Treated as `ask` — requires human approval | 0 if approved, 78 if timeout |

### Approval Flow

When a command requires approval (`ask` enforcement or no matching rule):

1. clawsudo creates an approval file path: `/tmp/clawsudo-<hash>.approved` (hash of the full command)
2. Sends a Slack notification with the command and approval instructions
3. Polls every 2 seconds for the approval file
4. If `touch /tmp/clawsudo-<hash>.approved` is run within 5 minutes → command executes
5. If timeout expires → command is denied (exit code 78)

### Slack Notifications

clawsudo loads webhook URLs from `/etc/clawav/config.toml` (or `./config.toml`):

```toml
[slack]
webhook_url = "https://hooks.slack.com/services/..."
```

Notifications are sent for:
- 🔴 **Denied commands** — critical alert with rule name
- ⚠️ **Pending approvals** — includes the `touch` command to approve
- 🔴 **No policy files** — critical fail-secure alert

### Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | General failure |
| 77 | Denied by policy |
| 78 | Approval timeout |

---

## 2. Policy Engine

ClawAV has two policy evaluation contexts that share the same YAML format:

- **clawsudo policies** — enforcement rules with `enforcement` field (allow/deny/ask); first match wins
- **Detection policies** — monitoring rules without `enforcement`; highest severity match wins

### YAML Policy Format

```yaml
rules:
  - name: "rule-name"
    description: "Human-readable description"
    match:
      command: ["binary1", "binary2"]        # Exact basename match
      command_contains: ["substring1"]        # Substring match on full command
      file_access: ["/etc/shadow", "/tmp/*.so"]  # Glob match (detection only)
      exclude_args: ["api.anthropic.com"]    # Whitelist — skip match if arg present
    action: critical    # critical | warning | info
    enforcement: deny   # allow | deny | ask (clawsudo only)
```

### Match Criteria

| Field | Description | Used By |
|---|---|---|
| `command` | List of binary basenames (case-insensitive) | clawsudo + detection |
| `command_contains` | Substrings matched against full command (case-insensitive) | clawsudo + detection |
| `file_access` | Glob patterns matched against file paths (uses `glob_match` crate) | Detection only |
| `exclude_args` | If any substring appears in args, the rule is skipped (whitelist) | Detection only |

> **Note:** clawsudo has its own independent policy loader (`src/bin/clawsudo.rs`) that only supports `command` and `command_contains` match criteria. The detection engine (`src/policy.rs`) supports all five criteria above.

### Rule Evaluation

**clawsudo:** First match wins. Order matters — deny rules must come before allow rules.

**Detection engine:** All rules are evaluated; the highest-severity match wins. Enforcement-only rules (those with `enforcement` field) are skipped in the detection pipeline. YAML files prefixed `clawsudo` are also skipped to avoid double-evaluation. The detection engine feeds into the alert pipeline — see [ALERT-PIPELINE.md](ALERT-PIPELINE.md) for how policy alerts are routed.

### Severity Levels

| Action | Severity | Rank |
|---|---|---|
| `critical` / `block` | Critical | 3 (highest) |
| `warning` | Warning | 2 |
| `info` | Info | 1 |

---

## 3. Admin Key System

ClawAV provides authenticated admin control via a Unix domain socket at `/var/run/clawav/admin.sock` (falls back to `/tmp/clawav-<uid>/admin.sock` if the primary path is unavailable).

### Key Generation

On first run, a 256-bit admin key is generated:

- **Format:** `OCAV-` prefix + 64 hex characters (e.g., `OCAV-a1b2c3...`)
- **Display once:** The key is printed to stderr in a banner and never stored in plaintext
- **Hash stored:** The Argon2id hash is written to the key hash file

### Argon2 Hashing

- Uses the `argon2` crate with default parameters (Argon2id)
- Random salt generated via `OsRng` for each hash
- Hash format: `$argon2id$v=19$m=...` (PHC string format)
- Verification uses constant-time comparison

### Key Management

```bash
# Key hash is stored at:
/etc/clawav/admin.key.hash

# To regenerate: delete the hash file and restart ClawAV
rm /etc/clawav/admin.key.hash
systemctl restart clawav
# New key will be printed — save it immediately
```

### Admin Socket Protocol

Clients send newline-delimited JSON over the Unix socket:

```json
{"key": "OCAV-...", "command": "status"}
{"key": "OCAV-...", "command": "pause", "args": {"minutes": 10}}
```

**Available commands:**

| Command | Description |
|---|---|
| `status` | Returns running state and pause status |
| `scan` | Triggers an on-demand scan |
| `pause` | Pauses monitoring (max 30 minutes, auto-resume) |
| `config-update` | Requests config reload |

### Rate Limiting

- **3 failed authentications** → 1-hour lockout
- Failed auth triggers a **Critical** severity alert
- Successful auth resets the failure counter
- Socket permissions: `0660` (owner + group only)

---

## 4. Audit Chain

A tamper-evident, hash-linked log (blockchain-style) that records every alert.

### How It Works

Each entry in the JSONL audit chain file contains:

```json
{
  "seq": 1,
  "ts": "2025-01-15T12:00:00Z",
  "severity": "critical",
  "source": "policy",
  "message": "Blocked: curl http://evil.com",
  "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "hash": "a1b2c3d4..."
}
```

### Hash Computation

Each entry's hash is SHA-256 over:
```
seq|ts|severity|source|message|prev_hash
```

- **Genesis entry** (seq 1): `prev_hash` is 64 zeros
- **Subsequent entries**: `prev_hash` is the hash of the previous entry
- This creates an unbreakable chain — modifying any entry invalidates all subsequent hashes

### Chain Resumption

When ClawAV restarts, `AuditChain::new()` reads the existing file, finds the last valid entry's sequence number and hash, and continues appending from there.

### Tamper Detection

Verify the entire chain:

```bash
clawav verify-audit                              # default path
clawav verify-audit /var/log/clawav/audit.chain  # custom path
```

Verification checks for each entry:
1. **Sequence continuity** — seq must increment by 1
2. **prev_hash linkage** — must match the previous entry's hash
3. **Hash integrity** — recomputed hash must match stored hash

```
✅ Audit chain verified: 1547 entries, all hashes valid
❌ Audit chain verification FAILED: Hash mismatch at seq 42
```

### Storage

- **Path:** `/var/log/clawav/audit.chain` (JSONL format)
- **clawsudo also appends** plain-text log lines to this file

---

## 5. API Key Proxy

A reverse proxy that prevents the AI agent from ever seeing real API credentials.

### How It Works

```
Agent → proxy (virtual key) → DLP scan → upstream API (real key)
```

1. Agent sends requests using a **virtual key** (e.g., `vk-anthropic-001`)
2. Proxy extracts the key from `x-api-key` (Anthropic) or `Authorization: Bearer` (OpenAI) headers
3. Looks up the virtual key in the key mapping table
4. Scans the request body for DLP violations
5. Replaces the virtual key with the real key
6. Forwards to the upstream API

### Key Mapping Configuration

```toml
[[proxy.key_mapping]]
virtual_key = "vk-anthropic-001"
real = "sk-ant-api03-REAL-KEY-HERE"
provider = "anthropic"
upstream = "https://api.anthropic.com"

[[proxy.key_mapping]]
virtual_key = "vk-openai-001"
real = "sk-REAL-KEY-HERE"
provider = "openai"
upstream = "https://api.openai.com"
```

### DLP (Data Loss Prevention) Scanning

Every outbound request body is scanned against configurable regex patterns:

| Pattern | Action | Example |
|---|---|---|
| SSN (`\d{3}-\d{2}-\d{4}`) | **block** | Request rejected with 403 |
| Credit card (`\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}`) | **redact** | Replaced with `[REDACTED]` |
| AWS key (`AKIA[0-9A-Z]{16}`) | **block** | Request rejected with 403 |

**DLP actions:**
- `block` — returns HTTP 403, sends Critical alert
- `redact` — replaces matched text with `[REDACTED]`, sends Warning alert, forwards modified request

---

## 6. LD_PRELOAD Guard

`libclawguard.so` is a shared library that intercepts libc syscalls at the lowest level, enforcing policy before the kernel ever sees the call.

### Build

```bash
gcc -shared -fPIC -o libclawguard.so src/preload/interpose.c -ldl
```

### Activation

```bash
export LD_PRELOAD=/usr/local/lib/libclawguard.so
# All child processes inherit this — syscalls are intercepted
```

### Intercepted Syscalls

| Syscall | What's Checked | Deny Condition |
|---|---|---|
| `execve` | Binary basename + args | Matches `deny_exec` patterns |
| `open` | File path (write mode only) | Prefix matches `deny_paths_write` |
| `openat` | File path (absolute, write mode) | Prefix matches `deny_paths_write` |
| `connect` | IP:port string | Substring matches `deny_connect` |

### Policy Configuration

The guard reads `/etc/clawav/preload-policy.json` once at library load (constructor):

```json
{
  "enabled": true,
  "log_file": "/var/log/clawav/preload.log",
  "deny_exec": ["bash -c", "sh -i", "nc", "ncat"],
  "deny_paths_write": ["/etc/clawav", "/etc/shadow", "/etc/sudoers"],
  "deny_connect": ["evil.com", ":4444"]
}
```

### Behavior

- **No policy file** → passthrough mode (all calls allowed)
- **`enabled: false`** → passthrough mode
- **Denied call** → returns `-1` with `errno = EACCES`, logs to `log_file`
- **Allowed call** → passes through to real libc function via `dlsym(RTLD_NEXT, ...)`

### How It Intercepts

The library uses the `LD_PRELOAD` mechanism to override libc functions. At load time (GCC `__attribute__((constructor))`), it:

1. Resolves real libc function pointers via `dlsym(RTLD_NEXT, "execve")` etc.
2. Reads and parses the JSON policy file (minimal hand-written parser, no malloc beyond initial read)
3. When the process calls `execve()`, `open()`, `openat()`, or `connect()`, the interposed version runs first
4. If denied, the call never reaches the kernel — it returns an error immediately

### Limitations

- Only checks absolute paths for `openat` (relative paths are not resolved)
- `deny_exec` pattern matching is simple: basename match, or `basename arg1` match
- Policy is loaded once at init — changes require process restart
- Max 64 rules per category, 256 chars per rule

---

## 7. Examples

### Common clawsudo Policy: Allow Package Management

```yaml
rules:
  - name: "allow-apt"
    match:
      command: ["apt", "apt-get", "dpkg"]
    action: info
    enforcement: allow
```

### Deny Dangerous Operations

```yaml
rules:
  - name: "deny-sudo-shell"
    description: "Never allow sudo to a raw shell"
    match:
      command: ["bash", "sh", "zsh", "dash"]
    action: critical
    enforcement: deny

  - name: "deny-firewall-disable"
    match:
      command_contains: ["ufw disable", "iptables -F"]
    action: critical
    enforcement: deny
```

### Require Approval for Unknown Commands

Any command that doesn't match a rule automatically enters the approval flow (5-minute timeout). No configuration needed — this is the default behavior.

### Detection Policy: Flag Exfiltration but Whitelist Known Hosts

```yaml
rules:
  - name: "block-data-exfiltration"
    description: "Flag curl/wget to unknown hosts"
    match:
      command: ["curl", "wget", "nc"]
      exclude_args:
        - "api.anthropic.com"
        - "github.com"
        - "localhost"
    action: critical
```

### LD_PRELOAD: Lock Down a Container

```json
{
  "enabled": true,
  "log_file": "/var/log/clawav/preload.log",
  "deny_exec": ["bash -i", "sh -i", "nc", "ncat", "python"],
  "deny_paths_write": ["/etc", "/usr/bin", "/usr/sbin"],
  "deny_connect": [":4444", ":1337", ":9001"]
}
```

### Full Defense-in-Depth Stack

```
┌─────────────────────────────────────────────┐
│  LD_PRELOAD guard (libclawguard.so)         │  ← Blocks at libc level
├─────────────────────────────────────────────┤
│  clawsudo (sudo proxy)                      │  ← Policy gate for privileged ops
├─────────────────────────────────────────────┤
│  API key proxy + DLP                        │  ← Credential isolation + data scanning
├─────────────────────────────────────────────┤
│  auditd + detection policy engine           │  ← Passive monitoring + alerting
├─────────────────────────────────────────────┤
│  Audit chain (hash-linked log)              │  ← Tamper-evident record
├─────────────────────────────────────────────┤
│  Admin socket (Argon2-authed)               │  ← Authenticated control plane
└─────────────────────────────────────────────┘
```
