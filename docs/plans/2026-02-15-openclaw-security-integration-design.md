# ClawAV × OpenClaw Security Integration — Design Document

> **Date:** 2026-02-15
> **Author:** Claw 🦞
> **Status:** Draft
> **Ref:** https://docs.openclaw.ai/gateway/security

## Problem

OpenClaw documents comprehensive security best practices — credential protection, config hardening, access control policies, plugin integrity, mDNS info leakage, session log protection. ClawAV already monitors the host OS but only scratches the surface of OpenClaw-specific security. The existing `scan_openclaw_security()` checks 4 things (gateway bind, auth, filesystem scope, tunnel). There's a whole attack surface being ignored.

## Goal

Make ClawAV the automated enforcement layer for everything in the OpenClaw security docs. If `openclaw security audit` can find it, ClawAV should find it faster, alert on it, and track drift over time.

## Architecture

Three layers, each building on the last:

```
┌──────────────────────────────────────────────────────┐
│                    PHASE 3                            │
│  mDNS info leak · Plugin integrity · Session log     │
│  access monitoring · Control UI exposure              │
├──────────────────────────────────────────────────────┤
│                    PHASE 2                            │
│  Config drift detection (diff-based)                 │
│  Policy regression alerts (dmPolicy, groupPolicy,    │
│  auth mode, sandbox, tool profiles)                  │
├──────────────────────────────────────────────────────┤
│                    PHASE 1                            │
│  openclaw security audit integration                 │
│  Credential path monitoring (sentinel)               │
│  OpenClaw permission checks (scanner)                │
└──────────────────────────────────────────────────────┘
```

### Phase 1: Audit Integration + Credential Monitoring

**1a. `openclaw security audit --deep` as a scan source**

Add a new scan category `openclaw:audit` that shells out to `openclaw security audit --deep --json` (if JSON output exists) or parses the text output. Run on the same interval as other periodic scans. Each finding maps to a `ScanResult` with appropriate severity.

Why not just run the CLI on cron? Because ClawAV aggregates all security findings into one alert stream with Slack notifications, TUI display, and audit chain. Running it inside ClawAV means findings are unified.

**1b. OpenClaw credential file monitoring**

Add these paths to sentinel's watched files (real-time inotify):

| Path | Policy | Rationale |
|------|--------|-----------|
| `~/.openclaw/openclaw.json` | watched | Config changes should be logged |
| `~/.openclaw/credentials/**` | protected | Credential theft detection |
| `~/.openclaw/agents/*/agent/auth-profiles.json` | protected | Model auth tampering |
| `~/.openclaw/agents/*/sessions/sessions.json` | watched | Session metadata changes |
| `~/.openclaw/credentials/whatsapp/*/creds.json` | protected | WhatsApp session theft |
| `~/.openclaw/credentials/*-allowFrom.json` | watched | Pairing allowlist changes |

"Protected" = quarantine + restore + CRIT alert. "Watched" = diff + INFO alert + auto-rebaseline.

**1c. OpenClaw permission checks**

Expand `scan_openclaw_security()` with:
- `~/.openclaw` directory permissions (must be 700)
- `openclaw.json` permissions (must be 600)
- Credential files not group/world-readable
- Session log files not group/world-readable
- Check for symlinks in `~/.openclaw` pointing outside (symlink attack vector)

### Phase 2: Config Drift Detection

**New module: `openclaw_config.rs`**

Parse `~/.openclaw/openclaw.json` and track security-critical fields. On each scan cycle, compare current values against last-known-good baseline. Alert on regressions:

| Field | Safe Value | Regression |
|-------|-----------|------------|
| `dmPolicy` | `pairing` or `allowlist` | Changed to `open` |
| `groupPolicy` | `allowlist` | Changed to `open` |
| `gateway.auth.mode` | `token` or `password` | Changed to `none` |
| `gateway.bind` | `loopback` / `127.0.0.1` | Changed to `0.0.0.0` |
| `sandbox.mode` | any non-empty | Turned off while exec tools enabled |
| `tools.profile` | `minimal` or scoped | Changed to `full` with open groups |
| `logging.redactSensitive` | `tools` | Changed to `off` |
| `controlUi.dangerouslyDisableDeviceAuth` | `false` | Changed to `true` |
| `controlUi.allowInsecureAuth` | `false` | Changed to `true` |

Baseline stored at `/etc/clawav/openclaw-config-baseline.json`. On first run, current config becomes baseline (no alert). Subsequent changes trigger alerts with a diff.

### Phase 3: Advanced Monitoring

**3a. mDNS info leak detection**

Check if Avahi/mDNS is broadcasting OpenClaw service info. Parse `avahi-browse -apt` output. Alert if:
- mDNS mode is `full` (leaks filesystem paths, SSH port)
- OpenClaw gateway service is advertised on a non-tailnet interface

**3b. Plugin/extension integrity**

Monitor `~/.openclaw/extensions/` via sentinel:
- New directory creation → INFO alert (new plugin installed)
- File modification in existing extension → WARN alert
- Track installed plugins and alert if count changes unexpectedly

**3c. Session log access monitoring**

Use auditd rules to watch `~/.openclaw/agents/*/sessions/*.jsonl` for reads by non-openclaw users. This catches:
- Other processes reading session transcripts (data exfiltration)
- Prompt injection via log exfiltration attempts

**3d. Control UI exposure**

Scanner check: if gateway has `controlUi` enabled, verify it's only accessible via loopback or Tailscale. Check for `dangerouslyDisableDeviceAuth` and `allowInsecureAuth` flags.

## What We're NOT Doing

- **Not replacing `openclaw security audit`** — we're wrapping it as a data source. Users can still run it manually.
- **Not auto-fixing** — ClawAV alerts, it doesn't modify OpenClaw config. The `--fix` flag is the user's choice.
- **Not monitoring model choice** — that's taste, not security.
- **Not blocking OpenClaw** — ClawAV is a watchdog, not a gatekeeper for the agent runtime.

## Config Changes

New TOML section in `config.toml`:

```toml
[openclaw]
enabled = true
config_path = "/home/openclaw/.openclaw/openclaw.json"
state_dir = "/home/openclaw/.openclaw"
audit_command = "openclaw security audit --deep"
audit_on_scan = true           # run audit CLI during periodic scans
config_drift_check = true      # phase 2: config drift detection
baseline_path = "/etc/clawav/openclaw-config-baseline.json"
mdns_check = true              # phase 3: mDNS info leak
plugin_watch = true            # phase 3: extension integrity
session_log_audit = true       # phase 3: auditd on session logs

# Additional sentinel watched paths (merged with existing)
[[openclaw.credential_paths]]
path = "/home/openclaw/.openclaw/credentials"
policy = "protected"
recursive = true

[[openclaw.credential_paths]]
path = "/home/openclaw/.openclaw/openclaw.json"
policy = "watched"
```

## Testing Strategy

- Unit tests for config parsing, drift detection logic, permission checks
- Integration tests that create temp directories with known permissions and verify scan results
- Mock `openclaw security audit` output for audit integration tests
- Sentinel tests with temp credential files

## Risk Assessment

- **Low risk:** Permission checks, credential monitoring — pure additions to existing scan/sentinel
- **Medium risk:** Config drift detection — needs careful JSON parsing, baseline management
- **Low risk:** mDNS/plugin monitoring — independent scan checks
- **Medium risk:** Audit CLI integration — depends on `openclaw` binary being available and output format stability
