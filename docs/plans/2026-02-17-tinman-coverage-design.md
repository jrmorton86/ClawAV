# Tinman Attack Coverage — Design Document

**Date:** 2026-02-17
**Context:** Cross-referencing the [Tinman OpenClaw Eval](https://github.com/oliveskin/tinman-openclaw-eval) harness (288 attack probes across 12 categories) against ClawTower v0.3.2 to identify and close detection gaps.

## Background

Tinman is a security evaluation harness that throws 288 attack probes at OpenClaw agents across 12 categories. Several map directly to OS-level behaviors ClawTower can detect but currently doesn't. This design adds detection for the 3 fully uncovered categories and hardens the 4 partially covered ones.

## Gap Analysis

### Already Covered (no changes needed)
| Tinman Category | ClawTower Module |
|---|---|
| Tool Exfiltration | behavior.rs (EXFIL_COMMANDS, AGENT_SENSITIVE_PATHS), sentinel, auditd cred_read rules |
| Privilege Escalation | clawsudo, behavior.rs (PRIV_ESC), scanner (SUID, sudoers) |
| Platform Specific (Linux) | Full coverage — auditd, iptables, kernel modules, AppArmor |
| Evasion Bypass | behavior.rs encoding tools, LD_PRELOAD detection, BarnacleDefense patterns |
| Supply Chain | BarnacleDefense supply-chain IOC DB, scanner package integrity |

### New Coverage Required

#### 1. Financial Transaction Detection (NEW — behavior.rs + sentinel)
**Tinman probes:** FT-* — wallet/seed phrase theft, transaction manipulation, approval hijacking.

**What ClawTower can detect at OS level:**
- Access to crypto wallet files (keystores, wallet.json, .env with keys)
- Commands containing seed/mnemonic/private_key patterns
- Reads of known crypto config directories
- `eth_sendTransaction` or similar RPC patterns in command args

**What ClawTower cannot detect (application-layer):**
- In-memory wallet operations within a running Node/Python process
- LLM generating transaction code without touching filesystem

#### 2. MCP Attack Detection (NEW — sentinel + behavior.rs)
**Tinman probes:** MCP-* — tool injection, server registration, cross-tool exfil.

**What ClawTower can detect:**
- MCP config file tampering (mcp.json, .mcp/, mcp-servers/)
- New MCP server registration (file creation in MCP dirs)
- MCP server processes spawning unexpected children

**What ClawTower cannot detect:**
- MCP wire protocol content (JSON-RPC over stdio/SSE is invisible to syscall monitoring)
- Logical tool misuse within a valid MCP session

#### 3. Context Bleed (OUT OF SCOPE)
**Tinman probes:** CB-* — cross-session leaks, conversation history extraction.

**Why out of scope:** Context bleed is an application-layer concern (session isolation within the LLM framework). ClawTower monitors OS syscalls — it has no visibility into session boundaries. The existing auditd rule `openclaw_session_read` partially covers filesystem-level session access, but true context bleed prevention requires application-layer hooks.

### Partial Coverage Hardening

#### 4. Prompt Injection Hardening (sentinel content scanning)
**Current:** BarnacleDefense injection DB matches patterns in auditd command lines.
**Gap:** Files written to agent-accessible dirs can contain embedded instructions that the agent later reads. No content scanning of downloaded/created files for injection markers.
**Fix:** Add injection marker patterns to sentinel content scanning for watched directories.

#### 5. Indirect Injection Hardening (sentinel + scanner)
**Current:** Sentinel watches config files, cognitive monitors identity files.
**Gap:** Downloaded documents, temp files, and fetched URLs can carry injections.
**Fix:** Sentinel watch on download/tmp directories; scanner check for injection markers in agent-accessible paths.

#### 6. Memory Poisoning Hardening (sentinel + behavior.rs)
**Current:** Cognitive baselines detect changes to SOUL.md etc.
**Gap:** Memory files (memory/*.md, MEMORY.md) are legitimately modified but could be poisoned with instructions.
**Fix:** Content scan memory file writes for injection patterns (not just change detection).

#### 7. Unauthorized Action (behavior.rs)
**Current:** Policy engine + clawsudo gate commands.
**Gap:** Agent API calls to external services (not via OS commands) are invisible.
**Fix:** Limited — add patterns for common CLI tools that perform destructive external actions (gh, aws, gcloud, az, twilio, sendgrid).

## Architecture

All changes follow existing patterns:
- **behavior.rs** — new const arrays + match blocks in `classify_behavior()`
- **sentinel watch_paths** — new default paths in `config.rs`
- **scanner** — new periodic scan functions
- **auditd** — new watch rules in `RECOMMENDED_AUDIT_RULES`

No new modules. No new dependencies. No architectural changes.

## New BehaviorCategory

Add `FinancialTheft` variant to the `BehaviorCategory` enum for wallet/crypto-specific detections, keeping it distinct from `DataExfiltration` for clearer alert triage.

## Risk

- **False positives:** Legitimate crypto development could trigger financial patterns. Mitigate with config allowlist for known dev paths.
- **Performance:** Additional sentinel watch paths add inotify watchers. Budget: <50 new watchers (well within kernel limits).
- **Content scanning load:** Injection marker scanning in sentinel is already implemented — just expanding the pattern set.
