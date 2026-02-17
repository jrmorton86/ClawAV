# Exfil Detection Fix — Design

**Date:** 2026-02-16
**Context:** Red Lobster v4 pentest — Flag 1 (EXFIL) bypassed 8/10 methods

## Problem

ClawTower's auditd pipeline has `-p r` watch rules that catch all reads at the kernel level, but the alert handler in `auditd.rs` only flags specific executables (`cp`, `tee`). 80% of exfil methods slip through undetected.

## Solution

**Allowlist-inverted alerting** — instead of alerting on known-bad executables, alert on everything *except* known-good ones. Plus a configurable `sensitive_files` section in the YAML config.

## Config Schema

```yaml
sensitive_files:
  - path: /home/openclaw/.openclaw/agents/main/agent/auth-profiles.json
    allow:
      - /usr/local/bin/node
    severity: Critical
  - path: /home/openclaw/.aws/credentials
    allow:
      - /usr/local/bin/node
      - /usr/bin/aws
    severity: Critical
  - path: /home/openclaw/.openclaw/gateway.yaml
    allow:
      - /usr/local/bin/node
    severity: Critical
  - path: /home/openclaw/.openclaw/workspace/SOUL.md
    allow:
      - /usr/local/bin/node
      - /usr/local/bin/clawtower
    severity: Warning
  - path: /home/openclaw/.openclaw/workspace/MEMORY.md
    allow:
      - /usr/local/bin/node
      - /usr/local/bin/clawtower
    severity: Warning
  - path: /home/openclaw/.openclaw/workspace/USER.md
    allow:
      - /usr/local/bin/node
      - /usr/local/bin/clawtower
    severity: Warning
```

## Changes to `auditd.rs`

1. **On startup:** Read `sensitive_files` from config, generate auditd `-w <path> -p r -k clawtower_sensitive_read` rules for each path
2. **On audit event with key `clawtower_sensitive_read`:** Extract the executable from the audit record, look up the file's allowlist, alert if exe is NOT in the allowlist
3. **Remove** the current hardcoded exe-matching logic for credential reads
4. **Alert format:** Include file path, reading executable, PID, severity from config

## What This Fixes

All 25 Red Lobster exfil methods go through `open()` → auditd catches every one → the inverted allowlist means `cat`, `dd`, `python3`, `base64`, `rsync`, `tar`, etc. all trigger alerts. Only `node` (OpenClaw) passes silently.

## What It Doesn't Cover

- Outbound network exfil (Flag 6 — separate work)
- A compromised `node` process exfiling through itself (would need content-level inspection, out of scope)

## Testing

- Update `redlobster-exfil.sh` to run all 25 methods
- Target: 25/25 detected (down from 2/10 in v4)
