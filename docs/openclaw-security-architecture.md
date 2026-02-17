# OpenClaw Security Architecture — ClawTower Reference

**Date:** 2026-02-16
**Source:** openclaw/openclaw repo (v2026.2.16)
**Purpose:** Security-relevant architecture for ClawTower monitoring

---

## 1. Trust Boundaries (5 layers)

OpenClaw defines 5 trust boundaries per their MITRE ATLAS threat model:

1. **Channel Access** — Gateway validates device pairing (30s grace), AllowFrom/AllowList, Token/Password/Tailscale auth
2. **Session Isolation** — Session key = `agent:channel:peer`; tool policies per agent; transcript logging
3. **Tool Execution** — Docker sandbox OR host (with exec-approvals); node remote execution; SSRF protection (DNS pinning + IP blocking)
4. **External Content** — Fetched URLs/emails/webhooks wrapped in XML tags with security notice injection
5. **Supply Chain** — ClawHub skill publishing with semver, SKILL.md required, pattern-based moderation, planned VirusTotal scanning

## 2. Process Execution & Sandbox

### Sandbox Model
- **Docker sandbox**: `Dockerfile.sandbox` — Debian bookworm-slim, runs as non-root `sandbox` user, minimal packages (bash, curl, git, jq, python3, ripgrep)
- **Also**: `Dockerfile.sandbox-browser` and `Dockerfile.sandbox-common` for browser-capable sandboxes
- **Host execution**: Available with exec-approval system (`exec-approval-manager.ts` in gateway)

### Process Management (`src/process/`)
- `child-process-bridge.ts` — Bridge for child process communication
- `exec.ts` — Core exec implementation
- `kill-tree.ts` — Process tree termination (recent PR: "graceful SIGTERM before SIGKILL")
- `spawn-utils.ts` — Spawn helpers (recent fix: `windowsHide: true`)
- `command-queue.ts` — Command queuing
- `supervisor/` — Process supervision subsystem
- `lanes.ts` — Execution lanes (resource management)
- `restart-recovery.ts` — Recovery from restarts

### Key Security Controls
- Tool policy system (`src/security/audit-tool-policy.ts`)
- Dangerous tools list (`src/security/dangerous-tools.ts`)
- Filesystem hardening: `tools.exec.applyPatch.workspaceOnly` and `tools.fs.workspaceOnly` configs

## 3. Gateway API & Auth

### Auth Stack (`src/gateway/`)
- `auth.ts` + `auth.test.ts` — Core authentication
- `auth-rate-limit.ts` — Rate limiting (but see open issue: "no rate limiting CWE-307")
- `http-auth-helpers.ts` — HTTP auth utilities
- `probe-auth.ts` — Probe authentication
- `device-auth.ts` — Device pairing auth
- `origin-check.ts` — Origin validation for CSRF protection
- `control-ui-csp.ts` — Content Security Policy for control UI
- `server-session-key.ts` — Session key management

### Binding & Exposure
- Default bind: **loopback only** (`127.0.0.1`/`::1`)
- Config: `gateway.bind="loopback"` (default)
- Canvas host paths (`/__openclaw__/canvas/`, `/__openclaw__/a2ui/`) treated as sensitive
- **NOT hardened for public internet exposure** — documented explicitly

### Node Execution Security
- `node-command-policy.ts` — Policy for remote node commands
- `node-invoke-sanitize.ts` — Input sanitization for node invocations
- `node-invoke-system-run-approval.ts` — Approval system for system-level node commands

## 4. Auth/Credential Storage

- Recent PR: "syncs all credential types to agent auth.json" — credentials stored in `auth.json` per agent
- Open security issue: **"Credential broker — separate secret storage from agent execution context"** (2026-02-12) — currently credentials are accessible within agent execution context, proposed separation
- Tool URL allowlist: Recent PR "add URL allowlist for web_search and web_fetch"

## 5. Security Audit System (`src/security/`)

Built-in security audit tooling:
- `audit.ts` — Core audit engine
- `audit-channel.ts` — Channel-specific audits
- `audit-extra.sync.ts` / `audit-extra.async.ts` — Extended audit checks
- `audit-fs.ts` — Filesystem permission audits
- `audit-tool-policy.ts` — Tool policy audits
- `fix.ts` — Auto-fix for audit findings
- `skill-scanner.ts` — ClawHub skill security scanning
- `scan-paths.ts` — Path scanning
- `secret-equal.ts` — Timing-safe secret comparison
- `external-content.ts` — External content sanitization
- `windows-acl.ts` — Windows ACL checks
- CLI: `openclaw security audit --deep` and `--fix`

## 6. Open Security Issues (Critical for ClawTower)

| Priority | Issue | Description |
|----------|-------|-------------|
| **CRITICAL** | Agent Routing Failure | Communication misdirection between agents |
| **HIGH** | Unrestricted Tool Execution | Privilege escalation via tool execution |
| **HIGH** | Gateway No Rate Limiting | CWE-307: brute-force auth possible |
| **HIGH** | Zero Prompt Injection Detection | No built-in detection (enabler for attacks) |
| **MEDIUM** | Credential Broker Missing | Secrets accessible in agent execution context |
| **MEDIUM** | Channel Webhooks No Schema Validation | Missing payload validation |
| **MEDIUM** | No Security Event Logging | Extension runtime has no audit trail |
| **MEDIUM** | Messaging Without Audit | Discord/Slack/Telegram ops unaudited |
| **LOW** | Hostname Info Disclosure | Developer hostnames in bundled skills |
| **LOW** | Error Info Leakage | Verbose errors in skills and third-party code |

### Proposed but not yet implemented:
- Tetragon TracingPolicies for kernel-level monitoring
- OTel span enrichment for security threat detection
- ClawHub manual security audits

## 7. Session Isolation Model

- Sessions keyed by `agent:channel:peer` triple
- Each session has its own conversation history (JSONL files)
- Tool policies are per-agent, not per-session
- Session memory with rotation (`session-memory` related PR)
- Subagent sessions are isolated but share the same filesystem/workspace

## 8. ClawTower Monitoring Recommendations

Based on this architecture, ClawTower should monitor:

1. **Gateway auth failures** — Watch for brute-force (no rate limiting confirmed)
2. **Exec tool invocations** — Especially outside sandbox, on host
3. **Credential file access** — `auth.json` reads/writes
4. **Node remote command execution** — Via `node-command-policy.ts` approval bypass
5. **External content fetching** — SSRF attempts despite DNS pinning
6. **Agent routing** — Cross-session message leakage (critical open bug)
7. **Skill installation** — ClawHub supply chain attacks
8. **Canvas/A2UI endpoints** — If exposed beyond loopback
9. **Process tree spawning** — Monitor for escape from sandbox containers
10. **WebSocket connections** — Gateway WS logging (`ws-log.ts`)

---

*Generated by ClawTower security research subagent, 2026-02-16*
