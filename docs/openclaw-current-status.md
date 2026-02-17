# OpenClaw Status Report

**Generated:** 2026-02-16 19:15 EST

## Version Status

| | Version |
|---|---|
| **Installed (package.json)** | `2026.2.13` |
| **Running (`--version`)** | `2026.2.13` |
| **Latest on npm** | `2026.2.15` |
| **npm wanted** | `2026.2.15` |

**⚠️ 2 versions behind.** Update available: `2026.2.13` → `2026.2.15`

Last update check: 2026-02-15T21:54:29Z (notified about 2026.2.14)

### Update Command
```bash
npm update -g openclaw
# Then: systemctl --user restart openclaw-gateway
```

## Gateway Configuration

- **Bind:** loopback only (`127.0.0.1:18789`) ✅
- **Service:** systemd user unit, running (PID 548390)
- **Dashboard:** http://127.0.0.1:18789/
- **Build hash:** 203b5bd

## Security-Relevant Configuration

### Exec & Browser
- **Browser sandbox:** `noSandbox: true` ⚠️ (Chromium runs without sandbox — typical for headless on Pi but reduces isolation)
- **Browser:** headless, enabled
- **No gateway.yaml** — all config in `openclaw.json`

### Agent Limits
- **Max concurrent agents:** 4
- **Max concurrent subagents:** 8
- **Compaction mode:** safeguard
- **Workspace:** `/home/openclaw/.openclaw/workspace`

### Channel Security
- **Slack groupPolicy:** `"open"` ⚠️ — any Slack user in allowed channels can interact with the agent
- **Allowed Slack channels:** 7 channels explicitly allowed
- **Ack reaction:** 🦞 on all channels

### Node Security
- **Denied node commands:** `camera.snap`, `camera.clip`, `screen.record`, `calendar.add`, `contacts.add`, `reminders.add`
- These are blocked from remote node invocation ✅

### Tool Policies
- **Exec:** No explicit sandbox/deny policy found in config (defaults apply)
- **Web search:** Brave API configured
- No explicit `toolPolicy` or `exec.sandbox` overrides detected

## ClawAV Integration Context

ClawAV (security watchdog) runs independently as root via systemd:
- **Binary:** `/usr/local/bin/clawav` (immutable flag)
- **Config:** `/etc/clawav/config.toml` (root-owned)
- **Monitors:** auditd logs, sentinel file watches, network policy
- **Policies:** YAML-based in `/etc/clawav/policies/`
- **clawsudo:** Enforces allow/deny lists for sudo commands

OpenClaw runs as `openclaw` user — ClawAV monitors this user's activity. The two systems are independent (different install paths, different service managers).

## Recommendations

1. **Update OpenClaw** to `2026.2.15` (2 versions behind)
2. **Review `groupPolicy: open`** — consider restricting if not all Slack workspace members should have agent access
3. **`noSandbox: true`** is expected on Pi/ARM but worth noting for security posture
4. **No exec sandbox policy** configured — relies on OS-level controls (auditd, clawsudo, AppArmor)
