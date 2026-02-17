# OpenClaw Release Audit for ClawTower

**Generated:** 2026-02-16  
**Scope:** Releases v2026.2.3 through v2026.2.15 (Feb 3–16, 2026)  
**Purpose:** Identify security-relevant changes affecting ClawTower monitoring

---

## Executive Summary

The last 2 weeks have seen **8 releases** with an extraordinary volume of security fixes — over 60 security-relevant changes. Key themes:

1. **Massive security hardening wave** (v2026.2.12–v2026.2.14): SSRF fixes, sandbox escapes blocked, webhook auth tightened across all channels
2. **Nested subagents** (v2026.2.15): Agents can now spawn sub-sub-agents — major new attack surface
3. **Hook session routing locked down** (v2026.2.12): Breaking change to `POST /hooks/agent` session key handling
4. **New plugin hooks** (v2026.2.15): `llm_input`/`llm_output` exposed — extensions can now observe all prompts
5. **Memory security** (v2026.2.14): LanceDB memory poisoning mitigations, auto-capture now opt-in

---

## Release-by-Release Analysis

### v2026.2.15 — 2026-02-16

#### HIGH Severity

| Change | Impact on ClawTower |
|--------|-------------------|
| **Nested sub-agents** (`maxSpawnDepth`, `maxChildrenPerAgent`) | ClawTower must monitor spawn depth chains. Agents can now create trees of sub-agents. Monitor `agents.defaults.subagents.maxSpawnDepth` config. Default depth=1, but configurable to 2+. |
| **Plugin hooks `llm_input`/`llm_output`** | Extensions can now observe ALL prompt content and model output. ClawTower should audit which plugins use these hooks — potential data exfiltration vector. |
| **Sandbox: block dangerous Docker config** (bind mounts, host networking, unconfined seccomp/apparmor) | Good — reduces container escape risk. ClawTower should verify this is active. |
| **Sandbox SHA-1→SHA-256 hashing** | Config cache identity now uses SHA-256. Existing sandbox fingerprints will change. |
| **Control UI: stored XSS fix** (assistant name/avatar) | Was exploitable — now patched. CSP `script-src 'self'` enforced. |
| **Workspace path sanitization** (Unicode control chars in dir names → prompt injection) | Good fix. ClawTower should still monitor for unusual workspace directory names. |
| **Skills `download` targetDir restricted** | Previously allowed arbitrary file writes via skill installers. Now confined to per-skill tools dir. |
| **Gateway status redaction** for non-admin clients | Session/path details no longer leaked to non-admin. ClawTower may need updated parsing if it reads status as non-admin. |

#### MEDIUM Severity

| Change | Impact on ClawTower |
|--------|-------------------|
| **Malformed session key rejection** (`agent:main` etc.) | Cross-session routing bug fixed. ClawTower should verify session key format validation. |
| **`chat.send` null byte/control char rejection** | Input sanitization hardened. Good for ClawTower. |
| **Web Fetch body size cap** | Prevents memory exhaustion from oversized pages. |
| **Cron webhook auth token** (`cron.webhookToken`) | New config key to monitor. |
| **LINE fail-closed on missing credentials** | Good — channels now refuse to start without proper auth. |

#### LOW Severity

| Change | Impact on ClawTower |
|--------|-------------------|
| Telegram bot token redaction from logs | Prevents accidental secret leakage. |
| Config sensitive-key whitelist case-insensitive | Prevents accidental redaction of `maxTokens`. |
| Git pre-commit hook option injection fix | Dev tooling hardening. |
| Discord role allowlist uses raw role IDs | Auth matching fix. |

---

### v2026.2.14 — 2026-02-15

#### HIGH Severity

| Change | Impact on ClawTower |
|--------|-------------------|
| **Memory LanceDB: escape injected memories + skip prompt-injection payloads** | Memory poisoning mitigated. Recalled memories now treated as untrusted. |
| **Memory LanceDB: `autoCapture` now opt-in (default disabled)** | **Breaking behavior change.** PII no longer auto-captured unless `autoCapture: true`. ClawTower should flag configs with this enabled. |
| **QMD/Security: `rawKeyPrefix` scope rules** | Fixes scoped deny bypass for agent-prefixed session keys. |
| **Sandbox file tools: bind-mount aware + read-only enforcement** | Container file access now respects bind mount semantics. |
| **Media security: harden local allowlist bypasses** | Explicit `readFile` override required. Filesystem-root `localRoots` rejected. |
| **Discord voice SSRF + local file read hardening** | Tool-supplied paths/URLs can no longer probe internal URLs. |
| **BlueBubbles: require `mediaLocalRoots` allowlists** | Prevents local file disclosure. |
| **Feishu: SSRF hardening** on media URL fetching. |
| **Hook transform modules restricted** to `~/.openclaw/hooks/transforms` | Prevents path traversal in hook config. `hooks.transformsDir` must be within that directory. |
| **Hook package manifest: ignore out-of-tree entries** | Prevents out-of-directory handler loads. |
| **Archive extraction: entry/size limits enforced** | Prevents zip bomb resource exhaustion. |
| **Skills archive extraction: path traversal blocked** | |
| **Slack DM command auth enforced even with `dmPolicy=open`** | Previously unauthorized users could run privileged commands via DM. |
| **iMessage: DM pairing identities excluded from group allowlist** | Prevents cross-context auth. |
| **Google Chat: reject ambiguous webhook routing** | Prevents cross-account misrouting. |
| **Telegram: require numeric sender IDs for allowlist** | `@username` no longer accepted — prevents impersonation. |
| **Telegram: require `webhookSecret`** | Unauthenticated webhook forgery blocked. |
| **Windows: no shell invocation for child processes** | Prevents cmd.exe metacharacter injection. |
| **Signal: harden archive extraction (path traversal)** | |
| **Zalo/Nostr/BlueBubbles: various auth hardening** | |
| **Security/Agents: scope CLI process cleanup to owned PIDs** | Prevents killing unrelated processes on shared hosts. |
| **Security/Agents: `apply_patch` path traversal + symlink escape blocked** | Non-sandbox mode now has workspace-root bounds. |
| **macOS keychain: shell injection fix** | |
| **macOS deep links: hard-limit unkeyed agent links** | |
| **Gateway: harden `gatewayUrl` overrides** (loopback/configured only) | |
| **Gateway: block `system.execApprovals.*` via `node.invoke`** | |
| **Gateway: reject oversized base64 chat attachments** | |
| **Gateway: stop returning secrets in `skills.status`** | |
| **SSRF: fix IPv4-mapped IPv6 bypass** | |
| **Browser: path traversal in upload/download** | |
| **Browser: CSRF hardening on loopback routes** | |
| **Node host: enforce `system.run` command consistency** | Prevents allowlist/approval bypass. |
| **Exec: `safeBins` allowlist bypass via shell expansion** | |
| **Exec: disable `node_modules/.bin` PATH bootstrapping by default** | |
| **Tlon: SSRF hardening** | |
| **Voice Call (Telnyx/Twilio): webhook signature verification required** | |
| **Discovery: stop trusting Bonjour TXT records for routing** | |
| **Security audit: new misconfiguration checks** added | |

#### MEDIUM Severity

| Change | Impact on ClawTower |
|--------|-------------------|
| **Outbound write-ahead delivery queue** | Messages now persist across gateway restarts. |
| **`sandbox.browser.binds`** config key | New config for browser container bind mounts. |
| **`dmPolicy` + `allowFrom` config aliases** | New config keys; legacy `dm.policy`/`dm.allowFrom` still work. |
| **Security/Gateway: canvas IP auth — public IPs now require bearer token** | **Breaking default-behavior change.** Only RFC1918/link-local/ULA/CGNAT accepted for IP-based auth. |
| **Security/Gateway: block high-risk tools from `/tools/invoke`** | `sessions_spawn`, `sessions_send`, `gateway`, `whatsapp_login` blocked by default. New config: `gateway.tools.{allow,deny}`. |
| **Config: `$schema` key now accepted** | |
| **Config: env `${VAR}` references preserved on write** | Secrets no longer persisted to disk during config writes. |
| **Config: overwrite audit logging** | New traceability for config changes. |
| **Android node: require HTTPS + SHA-256 for updates** | |

---

### v2026.2.13 — 2026-02-14

#### MEDIUM Severity

| Change | Impact on ClawTower |
|--------|-------------------|
| **Hugging Face provider support** | New provider to monitor in auth/model config. |
| **Plugin `message_sending` hooks** (thread-ownership gating) | Plugins can now cancel/modify outbound messages. |

#### LOW Severity

| Change | Impact on ClawTower |
|--------|-------------------|
| Pre-prompt context diagnostics added | Useful for debugging but no security impact. |
| GLM-5 synthetic catalog support | New model to track. |

---

### v2026.2.12 — 2026-02-13

#### HIGH Severity

| Change | Impact on ClawTower |
|--------|-------------------|
| **Breaking: `POST /hooks/agent` rejects `sessionKey` overrides by default** | Hooks can no longer hijack arbitrary sessions. New config: `hooks.defaultSessionKey`, `hooks.allowRequestSessionKey`, `hooks.allowedSessionKeyPrefixes`. **ClawTower must update hook monitoring.** |
| **OpenResponses: SSRF hardening** with hostname allowlists (`files.urlAllowlist`, `images.urlAllowlist`) | New config keys to audit. |
| **Nostr: unauthenticated remote config tampering fixed** | Critical vulnerability patched. |
| **Sandbox: skill sync path traversal blocked** | Frontmatter-controlled skill names no longer used as filesystem paths. |
| **Web tools: browser/web content treated as untrusted** | `toolResult.details` stripped from model-facing transcript. Reduces prompt injection replay. |
| **Webhook/device token: constant-time comparison + per-client throttling** | Auth timing attacks mitigated. 429 rate limiting added. |
| **Browser control: auth now required for loopback routes** | `gateway.auth.token` auto-generated if missing. Security audit check added. |
| **Session transcript path hardening** | Unsafe session IDs/paths rejected. |
| **BlueBubbles webhook auth bypass via loopback proxy trust fixed** | |
| **Bundled `soul-evil` hook removed** | |
| **Skill/plugin code safety scanner added** | |
| **Credentials redacted from `config.get` responses** | |

#### MEDIUM Severity

| Change | Impact on ClawTower |
|--------|-------------------|
| **`OPENCLAW_HOME` env var** | New path override. ClawTower must account for non-default home dirs. |
| **Agent management RPCs** (`agents.create`, `agents.update`, `agents.delete`) | New gateway API surface to monitor. |
| **Grok (xAI) web search provider** | New tool provider. |
| **`sessions_history` payload cap** | Context overflow mitigation. |
| WS payload limit raised to 5MB | Larger attachments now possible. |
| Gateway drains active turns before restart | Better reliability but changes shutdown behavior. |

---

### v2026.2.9 — 2026-02-09

#### MEDIUM Severity

| Change | Impact on ClawTower |
|--------|-------------------|
| **iOS alpha node app** | New node type — phone control via plugins. |
| **Device pairing plugins** | Telegram `/pair`, iOS/Android node controls. New pairing surface. |
| **`OPENCLAW_HOME`** path override | (Also in 2.12) |
| **Canvas auth required** | Good — was previously unauthenticated. |

---

### v2026.2.6 — 2026-02-07

#### MEDIUM Severity

| Change | Impact on ClawTower |
|--------|-------------------|
| **Canvas host auth required** | Security fix — canvas assets now need auth. |
| **Skill/plugin code safety scanner** | New audit tool. |
| **Credentials redacted from gateway `config.get`** | Prevents secret leakage. |

---

### v2026.2.3 — 2026-02-05

#### HIGH Severity

| Change | Impact on ClawTower |
|--------|-------------------|
| **Untrusted channel metadata excluded from system prompts** (Slack/Discord) | Prevents prompt injection via channel names/topics. |
| **Sandboxed media paths enforced for message tool attachments** | |
| **Gateway URL overrides require explicit credentials** | Prevents credential leakage. |
| **`whatsapp_login` gated to owner senders** | |

#### MEDIUM Severity

| Change | Impact on ClawTower |
|--------|-------------------|
| **Cron: major delivery mode overhaul** | Announce mode default for isolated jobs. `deleteAfterRun` default. Legacy fields dropped. |
| **Per-channel `responsePrefix` overrides** | New config surface. |

---

## Recent Commits (post-v2026.2.15)

| SHA | Date | Description | Relevance |
|-----|------|-------------|-----------|
| `076df941` | Feb 16 | **Configurable tool loop detection** | **MEDIUM** — New safety feature. ClawTower should monitor `toolLoopDetection` config. |
| `dacffd7a` | Feb 16 | Fix Windows bind mount parsing in sandbox | LOW |
| `b3d0e0cb` | Feb 16 | Cron: preserve overrides, harden next-run calc | LOW |
| Various refactors | Feb 16-17 | Code dedup/cleanup | LOW — no behavioral changes |

---

## Summary: What ClawTower Must Update

### Immediate (HIGH priority)

1. **Monitor nested subagent spawning** — Track `maxSpawnDepth` config and actual spawn depth in runtime. Alert on depth > 1.
2. **Audit `llm_input`/`llm_output` plugin hooks** — Any extension using these can exfiltrate all prompts and outputs.
3. **Verify hook session routing lockdown** — Ensure `hooks.allowRequestSessionKey` is not set to `true` unless intentional.
4. **Track `apply_patch` usage** — Now has path bounds in non-sandbox mode, but still worth monitoring.
5. **Monitor `autoCapture` config** — Flag any config with `autoCapture: true` (memory poisoning risk).
6. **Update gateway tools deny list monitoring** — Track `gateway.tools.{allow,deny}` for `/tools/invoke` access.
7. **Verify browser control auth** — Ensure `gateway.auth.token` is set when browser control is active.

### Short-term (MEDIUM priority)

8. **Track new config keys**: `sandbox.browser.binds`, `dmPolicy`, `allowFrom`, `cron.webhookToken`, `hooks.defaultSessionKey`, `hooks.allowedSessionKeyPrefixes`, `files.urlAllowlist`, `images.urlAllowlist`, `hooks.transformsDir`
9. **Monitor new providers**: Hugging Face, xAI/Grok, vLLM — new auth surfaces.
10. **Track agent management RPCs** (`agents.create/update/delete`) — who can create/modify agents.
11. **Monitor `OPENCLAW_HOME` usage** — non-default paths could bypass path-based monitoring.
12. **Verify canvas IP auth change** — public IPs now need bearer tokens.
13. **Monitor tool loop detection** config (new feature in HEAD).

### Ongoing

14. **SSRF protections** — Massive wave of fixes across all channels. Verify ClawTower's own URL handling is safe.
15. **Webhook auth** — Many channels now require proper secrets. Flag missing `webhookSecret` configs.
16. **Archive extraction** — Size/entry limits now enforced. Monitor for skill/plugin installs.
