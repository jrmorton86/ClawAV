# ClawTower Enterprise: Agent-Agnostic Runtime Security for the AI Era

**Date:** 2026-02-18
**Status:** Design (pending implementation)
**Audience:** Engineering, Security, Product, Enterprise GTM
**Cross-references:**
- `docs/findings-2026-02-18-enterprise-readiness.md` (gap analysis input)
- `docs/plans/2026-02-18-enterprise-agent-security-hardening-roadmap.md` (tactical hardening plan)
- `docs/plans/2026-02-17-response-engine-design.md` (response engine, referenced by Phase 2)

---

## Why This Plan Exists

Three converging developments in the week of 2026-02-17 shifted the enterprise AI agent security market:

1. **Corporate bans on OpenClaw.** Meta, Microsoft, and others formally banned OpenClaw from corporate networks after CVE-2026-25253 (one-click RCE, 21,000+ reachable instances). The core concern: agents with system-wide permissions and no oversight.

2. **ClawHavoc supply chain attack.** 1,184 malicious skills found on ClawHub — nearly 20% of the marketplace. Attack vectors include fake prerequisites installing AMOS malware, dormant backdoors triggered by specific prompts, and credential exfiltration from `.env` files.

3. **Identity-first security for agents.** CyberArk (acquired by Palo Alto Networks for $25B) argues that identity and privilege failures — not model failures — drive AI security risks. Their framework: treat agents as identities, enforce least privilege with JIT access, remove standing access, monitor continuously.

Additionally, the enterprise readiness findings report (`findings-2026-02-18-enterprise-readiness.md`) identified privileged command governance (clawsudo policy scope) as the #1 enterprise adoption blocker, validated by Red Lobster v8 pentest results.

### Sources

- Meta banning OpenClaw: https://www.techbuzz.ai/articles/meta-bans-viral-ai-tool-openclaw-over-security-risks
- OECD incident report (CVE-2026-25253): https://oecd.ai/en/incidents/2026-02-16-bab5
- ClawHavoc (GBHackers): https://gbhackers.com/clawhavoc-infects-openclaws-clawhub/
- ClawHavoc technical analysis (Snyk): https://snyk.io/articles/clawdhub-malicious-campaign-ai-agent-skills/
- Bitdefender enterprise advisory: https://businessinsights.bitdefender.com/technical-advisory-openclaw-exploitation-enterprise-networks
- ClawHavoc defense recommendations (Security Boulevard): https://securityboulevard.com/2026/02/securing-openclaw-againstclawhavoc/
- CyberArk agents-as-identities thesis: https://www.cyberark.com/resources/blog/why-reducing-ai-risk-starts-with-treating-agents-as-identities
- Palo Alto / CyberArk acquisition: https://www.paloaltonetworks.com/company/press/2026/palo-alto-networks-completes-acquisition-of-cyberark-to-secure-the-era-of-ai-agents

---

## Strategic Positioning

### The Three-Layer Model

The AI agent security market splits into three layers, and most vendors fight over the top two:

1. **Model layer** — prompt guardrails, output filtering (Anthropic, OpenAI doing this themselves)
2. **Identity layer** — agent credentials, privilege management (CyberArk/Palo Alto's $25B bet)
3. **Runtime layer** — OS-level behavior monitoring, syscall auditing, file integrity, network policy enforcement

ClawTower owns layer 3. Nobody else does this well.

### Positioning Against the News Cycle

| Event | ClawTower's Answer |
|-------|-------------------|
| Meta/Microsoft banning OpenClaw | "Don't ban agents. Cage them. ClawTower enforces behavioral policy at the OS level — any agent, any framework." |
| ClawHavoc supply chain attack | "ClawTower detects malicious skill behavior at runtime, even when the marketplace fails to catch it at install time." |
| CyberArk's identity thesis | "We agree — and we're the enforcement layer. CyberArk manages who the agent is. ClawTower watches what it does." |

### Key Differentiator

ClawTower is tamper-proof from the agent's perspective. The swallowed key pattern means the agent cannot stop, modify, or disable its own oversight. No other product in this space makes that claim. This is the moat.

### Target

- **Primary buyer:** Enterprise security teams (CISOs, security ops)
- **Positioning:** Agent-agnostic — not tied to OpenClaw or any single framework
- **Deployment model:** On-prem agents with SaaS management plane (CrowdStrike/SentinelOne architecture)

---

## Architecture: SaaS Management Plane

ClawTower agents run on-prem (same host as the AI agent), reporting up to a centralized cloud management plane.

```
+-----------------------------------------------------------+
|                  ClawTower Cloud (SaaS)                    |
|                                                            |
|  +------------+  +-----------+  +------------+  +--------+ |
|  | Fleet Mgmt |  | Alert     |  | Compliance |  | Agent  | |
|  | Dashboard  |  | Agg/SIEM  |  | Reports    |  | Repo   | |
|  +-----+------+  +-----+-----+  +------+-----+  +---+----+ |
|        +-----------------+---------------+-----------+      |
|                          | gRPC/mTLS                        |
+--------------------------|----------------------------------+
                           |
           +---------------+---------------+
           |               |               |
    +------+------+  +-----+-------+  +----+--------+
    | Host A       |  | Host B       |  | Host C       |
    | +----------+ |  | +----------+ |  | +----------+ |
    | |ClawTower | |  | |ClawTower | |  | |ClawTower | |
    | |  Agent   | |  | |  Agent   | |  | |  Agent   | |
    | +----+-----+ |  | +----+-----+ |  | +----+-----+ |
    |      | watch |  |      | watch |  |      | watch |
    | +----+-----+ |  | +----+-----+ |  | +----+-----+ |
    | | OpenClaw | |  | |  Devin   | |  | |Claude Code| |
    | +----------+ |  | +----------+ |  | +----------+ |
    +--------------+  +--------------+  +--------------+
```

### Design Decisions

- **Agent autonomy preserved.** If the cloud is unreachable, ClawTower agents continue operating locally with full detection/response capability. The cloud is for management and aggregation, never for enforcement decisions. This matters for air-gapped or regulated environments.

- **Uplink channel.** Agents push alerts, audit chain entries, and health telemetry to the cloud via mTLS gRPC. The cloud pushes policy updates and config changes down. The existing audit chain hash-linking means the cloud can verify it received a complete, untampered alert stream from each agent.

- **Agent registration.** Each ClawTower instance registers with a unique agent ID + Ed25519 keypair (reuses existing Ed25519 infrastructure from update verifier). The cloud authenticates agents by their key, not by network position.

- **Multi-tenancy at the cloud layer, not the agent.** Each on-prem ClawTower still monitors one host. The cloud handles fleet grouping, RBAC, and org isolation. This keeps the agent simple and tamper-proof.

---

## Agent Profile Abstraction

Today, OpenClaw is hardcoded in several places — cognitive file paths (`SOUL.md`, `IDENTITY.md`), the `OpenClawConfig` section, behavior patterns referencing OpenClaw-specific paths. This is replaced with a generic Agent Profile system.

An Agent Profile is a TOML declaration that tells ClawTower how to monitor a specific agent framework. It defines what to watch, not how to watch it.

```toml
# /etc/clawtower/agents.d/openclaw.toml
[agent]
name = "openclaw"
display_name = "OpenClaw"
user = "openclaw"                    # UID or username to monitor
home = "/home/openclaw"

[agent.identity_files]
# Files that define the agent's identity — protected (critical alert on change)
protected = [
    "SOUL.md", "IDENTITY.md", "TOOLS.md",
    "AGENTS.md", "USER.md", "HEARTBEAT.md"
]
# Files that evolve — watched (info alert, auto-rebaseline)
watched = ["MEMORY.md"]

[agent.sensitive_paths]
# Agent-specific files containing secrets
env_files = [".env", ".clawdbot/.env"]
config_files = ["config.yaml"]

[agent.skill_paths]
# Where this agent installs skills/plugins — for supply chain scanning
directories = ["/home/openclaw/.openclaw/skills"]
manifest = "SKILL.md"               # Expected manifest filename

[agent.network]
# Agent-specific network policy overrides
allowed_hosts = ["api.anthropic.com", "api.openai.com"]
```

### Codebase Changes

- `OpenClawConfig` in `config.rs` replaced by `Vec<AgentProfile>` loaded from `agents.d/`
- `cognitive.rs` hardcoded paths read from `agent.identity_files`
- `behavior.rs` OpenClaw-specific patterns parameterized by agent profile
- `sentinel.rs` auto-generates watch paths from all loaded agent profiles
- New CLI: `clawtower agent list`, `clawtower agent add <framework>`

### Shipped Profiles

Curated profiles maintained for OpenClaw, Claude Code, Devin, Cursor Agent, and a `generic.toml` template. Community can contribute more. The engine is generic; the intelligence is in the profiles.

---

## Pillar 1: Supply Chain Defense

Directly addresses ClawHavoc. The attack succeeded because ClawHub has no verification and agents blindly trust installed skills. Defense operates at three layers.

### Layer 1: Skill Manifest Verification (install-time)

When a skill is installed into any path defined in `agent.skill_paths`, sentinel fires an inotify event and triggers a skill intake scan:

- Parse the manifest file (e.g., `SKILL.md`, `package.json`, `pyproject.toml`) — extract declared dependencies, entry points, required permissions
- Static scan of all skill files against BarnacleDefense pattern DBs — `supply-chain-ioc.json` already catches code evaluation calls, base64-encoded payloads, known C2 domains
- Check declared permissions against agent profile's allowlist — a "YouTube summarizer" skill requesting filesystem access is suspicious
- Hash the entire skill directory and store in a local skill manifest ledger (append-only, hash-chained like audit chain)

### Layer 2: Runtime Behavior Fencing (execution-time)

Even if a skill passes install-time scanning, ClawHavoc's dormant backdoors activate at runtime. Existing detection already catches reverse shells, credential file access, unexpected network connections, and process spawning chains.

New addition: **per-skill behavioral attribution.** Today, all syscalls from a monitored UID look the same. With agent profiles, we correlate process trees back to which skill initiated them. A skill's process spawns `curl` to an unknown host — the alert names the specific skill, not just the agent.

### Layer 3: Fleet-Level Skill Intelligence (cloud)

The SaaS management plane aggregates skill manifests across all ClawTower agents in an org:

- **Skill reputation database** — if a skill hash triggers alerts on 3+ hosts, auto-flag it fleet-wide
- **Organizational skill allowlist** — security team approves skills centrally, agents enforce locally
- **Live IOC feed** — publish and consume IOC feeds for known-malicious skill hashes, C2 domains, and behavioral signatures. The existing `supply-chain-ioc.json` becomes a live-updated feed rather than a static file

### Cognitive Social-Engineering Detector

From findings P2.3. Catches the ClawHavoc vector where skills trick the LLM into telling the user to run malicious commands. New pattern set for:

- Base64-piped installer chains in watched files
- External script fetch instructions in documentation (`curl ... | sh`, `wget -O- ... | bash`)
- Password-protected archive instructions
- References to known paste/snippet services (rentry, glot, pastebin) in skill files

Applied to both command stream AND content of sentinel-watched files (skill manifests, READMEs).

### Flow

```
Skill installed -> Sentinel detects -> Intake scan
    |                                      |
    | PASS                            FAIL |-> Quarantine + Critical alert
    v
Runtime monitoring (existing pipeline)
    |
    | Suspicious behavior
    v
Per-skill attribution -> Alert with skill name
    |
    | Cloud uplink
    v
Fleet correlation -> Auto-flag if seen on multiple hosts
```

We are NOT building a marketplace or skill signing PKI. That is the marketplace's problem. ClawTower is the runtime immune system — it catches what the marketplace misses.

---

## Pillar 2: Agent Identity & Capability Envelope

CyberArk's thesis is right: identity and privilege failures drive AI security risks. But they solve it at the IAM layer (credentials, OAuth tokens, JIT access). ClawTower solves it at the enforcement layer — what the agent can actually do on the host, regardless of what credentials it holds.

### The Problem Today

ClawTower monitors and alerts. clawsudo gates sudo commands. But there is no unified privilege model that says "this agent is allowed to read files, call these 3 APIs, and nothing else." The agent's effective permissions are whatever the Linux user can do, minus what clawsudo blocks. That is deny-by-pattern, not allow-by-policy.

### Agent Capability Envelope

Each agent profile gets a capability envelope — a declarative description of what the agent is permitted to do. Everything outside the envelope is a violation.

```toml
# In agents.d/openclaw.toml
[agent.capabilities]
# Filesystem: what paths the agent may read/write
fs_read = ["/home/openclaw/**", "/tmp/openclaw-*"]
fs_write = ["/home/openclaw/workspace/**"]
fs_deny = ["/etc/**", "/var/log/**", "/root/**"]

# Network: outbound connections permitted
net_allow = ["api.anthropic.com:443", "api.openai.com:443", "github.com:443"]
net_deny_all_other = true

# Process: what the agent may execute
exec_allow = ["python3", "node", "git", "ls", "cat", "grep"]
exec_deny = ["curl", "wget", "nc", "ssh", "docker"]

# Privilege: sudo behavior
sudo = "clawsudo"  # all sudo goes through clawsudo
escalation = "deny" # no suid, no capability grants

# Resource limits
max_processes = 50
max_open_files = 1024
max_network_connections = 20
```

### Layered Enforcement

| Layer | Mechanism | Already Have? |
|-------|-----------|---------------|
| Sudo gating | clawsudo policy evaluation | Yes |
| Syscall monitoring | auditd + behavior engine | Yes |
| Network policy | netpolicy allowlist/blocklist | Yes |
| File integrity | sentinel inotify | Yes |
| **Capability matching** | **Compare observed behavior against envelope** | **New** |
| **Violation response** | **Response engine playbooks** | **Designed** |

The key new piece is the **capability matcher** — a module that sits in the aggregator pipeline. Every alert that flows through gets checked against the agent's declared capability envelope. An alert within the envelope gets downgraded or suppressed. An alert outside the envelope gets upgraded and tagged as a **policy violation** (`envelope_violation` category).

### Agent Identity Registry

Each loaded agent profile gets a runtime identity record:

- `agent_id`: deterministic from profile name + host
- `trust_level`: untrusted / limited / trusted / privileged
- `risk_score`: computed from recent alert volume
- `lifecycle_state`: active / suspended / revoked

API endpoints: `GET /api/agents`, `GET /api/agents/{id}`, `PATCH /api/agents/{id}`

Every alert tagged with `agent_id`. Identity state changes generate their own alerts and audit chain entries.

### Credential Scoping + Ephemeral Keys

Proxy key mappings gain `ttl` and `scope` fields:

- **TTL:** key expires after N minutes, agent must re-request via admin socket
- **Scope:** key only valid for specific API endpoints or methods (e.g., "chat completions only, no fine-tuning")
- **Auto-revoke:** keys revoked when agent's risk score exceeds threshold or trust level drops
- **Audit:** every key issuance and revocation recorded in audit chain

### Signed IOC Bundle Lifecycle

IOC JSON databases gain a version header + Ed25519 signature:

- `clawtower update-iocs` fetches latest signed bundle from cloud or GitHub
- Each alert records which IOC bundle version made the detection
- Rollback: keep previous 3 signed bundles, admin can revert if false-positive spike

### Dynamic Authorization Hooks

Integrates with response engine design. Policy expression in YAML:

```yaml
# policies/dynamic-auth.yaml
- name: high-risk-network-access
  when:
    risk_score: ">= 70"
    action: "net_connect"
    target_not_in: "agent.capabilities.net_allow"
  then: "deny"

- name: elevated-fs-write
  when:
    trust_level: "limited"
    action: "fs_write"
    target_in: "/etc/**"
  then: "require_approval"
```

### Why This Matters for Enterprise

- Security teams define capability envelopes per agent role, not per host
- Envelopes pushed from cloud management plane for consistent fleet policy
- Audit trail shows "Agent X violated its envelope by accessing /etc/shadow" — not just "UID 1000 read /etc/shadow"
- Maps directly to CyberArk's "least privilege" language — enforced at the OS level

CyberArk controls what credentials the agent has. ClawTower controls what the agent can do with any credentials. Both are needed. ClawTower's enforcement cannot be bypassed by a compromised credential because it watches syscalls, not tokens.

---

## Pillar 3: SIEM & Compliance Export

No enterprise security team will adopt a tool that does not plug into their existing SOC stack. Today, ClawTower's audit chain is a local JSONL file. That is invisible to their security operations.

### Export Pipeline

New export stage parallel to existing Slack/TUI/API:

```
Aggregator
    |-->  alert_tx  -> TUI
    |-->  slack_tx  -> Slack
    |-->  api_store -> HTTP API
    |-->  audit_chain -> local JSONL (unchanged)
    +-->  export_tx -> Export Pipeline (NEW)
                        |-- Syslog (RFC 5424/CEF)
                        |-- Webhook (generic JSON POST)
                        |-- Cloud uplink (gRPC to mgmt plane)
                        +-- File (rotated JSON for Splunk forwarder)
```

### Format Support

| Format | Target | Why |
|--------|--------|-----|
| **Syslog CEF** (Common Event Format) | Splunk, QRadar, ArcSight, any SIEM | Industry standard. UDP/TCP/TLS. Every SOC already ingests this. |
| **JSON webhook** | SOAR platforms, PagerDuty, Tines, custom | POST to a URL on every alert. Simple, composable. |
| **gRPC uplink** | ClawTower Cloud | Structured protobuf for fleet aggregation. Also carries audit chain + telemetry. |

Syslog CEF mapping example:

```
CEF:0|ClawTower|ClawTower|0.4.0|supply_chain:skill_intake|
  Malicious skill detected|9|src=openclaw dst=/home/openclaw/.skills/yt-summarize
  msg=ClawHavoc C2 pattern matched cat=supply-chain
```

### Configuration

```toml
[export]
enabled = true

[export.syslog]
enabled = true
target = "tcp://siem.corp.internal:6514"
format = "cef"         # or "rfc5424"
tls = true
min_level = "warning"

[export.webhook]
enabled = true
url = "https://hooks.corp.internal/clawtower"
auth_header = "Bearer ${WEBHOOK_TOKEN}"
batch_size = 10
flush_interval = 5

[export.cloud]
enabled = true
endpoint = "https://api.clawtower.io"
agent_key_path = "/etc/clawtower/agent-key.pem"
```

### Compliance Report Generation

`clawtower compliance-report --framework soc2 --period 30d --output report.pdf`

Maps alert categories to framework controls:

| ClawTower Category | SOC 2 Control | NIST 800-53 | CIS Control |
|-------------------|---------------|-------------|-------------|
| `behavior:data_exfiltration` | CC6.1, CC7.2 | SC-7, SI-4 | 13.1 |
| `behavior:privilege_escalation` | CC6.1, CC6.3 | AC-6, AU-12 | 5.4 |
| `sentinel:file_integrity` | CC8.1 | SI-7 | 3.14 |
| `scan:firewall_status` | CC6.6 | SC-7 | 4.8 |
| `capability:envelope_violation` | CC6.1, CC6.8 | AC-3, AC-25 | 6.1 |
| `audit_chain:tamper_detected` | CC7.2, CC7.3 | AU-9, AU-10 | 8.11 |

Report includes: alert summary by control, envelope violation count, scanner pass/fail rates, audit chain integrity verification, incident mode activations. JSON export variant for programmatic consumption. Cloud management plane generates fleet-aggregated reports.

We are NOT building a SIEM. The customer's existing SIEM is the system of record. ClawTower is a data source, not a replacement.

---

## Gap Analysis: Cross-Reference with Findings Report

The enterprise readiness findings report (`findings-2026-02-18-enterprise-readiness.md`) identified items that this design incorporates:

### Items from findings incorporated into this design

| Finding | Findings Reference | Where Addressed |
|---------|-------------------|-----------------|
| clawsudo policy too broad | Finding A + B, P0.1 | Phase 0 (P0.1) |
| sudoers risk scanner | P0.2 | Phase 0 (P0.2) |
| Incident mode toggle | P0.3 | Phase 0 (P0.3) |
| Agent identity lifecycle | Finding C, P1.1 | Phase 2 (Pillar 2, identity registry) |
| Hostile marketplace defaults | Finding D, P2.1 | Phase 1 (Pillar 1, skill intake scanner) |
| Cognitive social-engineering detector | P2.3 | Phase 1 (Pillar 1, social-engineering detector) |
| Signed IOC lifecycle | P2.2 | Phase 2 (Pillar 2, signed IOC bundles) |
| Capability-scoped credentials | P1.2 | Phase 2 (Pillar 2, ephemeral keys) |
| Dynamic authorization hooks | P1.3 | Phase 2 (Pillar 2, dynamic auth) |
| Tiered default profiles | P3.2 | Phase 0 (P0.4) |
| Control matrix + evidence export | P3.1 | Phase 3 (Pillar 3, compliance reports) |
| Buyer-facing artifacts | P3.3 | Phase 3 (P3.4) |

### Items in this design NOT in the findings (new additions)

| Design Element | Pillar | Rationale |
|----------------|--------|-----------|
| Agent Profile abstraction (`agents.d/`) | Section 3 | Makes agent-agnostic positioning real at the code level |
| SaaS management plane | Section 2 | Enterprise deployment model, fleet management |
| SIEM export pipeline (syslog CEF, webhook, gRPC) | Pillar 3 | Enterprise SOC integration — dealbreaker without it |
| Fleet-level skill intelligence | Pillar 1 | Cross-host reputation requires cloud aggregation |
| Per-skill behavioral attribution | Pillar 1 | Granular runtime accountability per skill |
| Capability envelope as aggregator-level matcher | Pillar 2 | Integrates identity model with existing alert pipeline |

---

## Phased Roadmap

### Phase 0 — Close the Front Door (Week 1)

Pure hardening. No new architecture, no new modules. Fix the known privilege escalation paths that Red Lobster v8 proved exploitable.

**P0.1: clawsudo enterprise profile**

Files: `policies/clawsudo-enterprise.yaml`, `src/bin/clawsudo.rs` tests

- Ship `policies/clawsudo-enterprise.yaml` alongside the existing policy
- Remove `allow-file-ops` broad rule — replace with explicit read-only allowlist (`cat`, `ls`, `stat`, `head`, `tail`, `wc` only)
- Restrict `allow-systemctl` to `status` and `is-active` only
- Explicit deny entries for: `find` with `-exec`, `sed -e`/`sed -i` to sensitive paths, `tee` to `/etc/**`, `chmod +s`, any write to `sudoers`

Acceptance: Red Lobster v8 flag 15/16 privilege abuse paths 100% denied.

**P0.2: sudoers risk scanner**

Files: `src/scanner.rs`

- New `scan_sudoers_risk()` function
- Parse `/etc/sudoers` and `/etc/sudoers.d/*` for NOPASSWD entries
- Cross-reference against GTFOBins-capable binaries (`find`, `sed`, `tee`, `cp`, `mv`, `chmod`, `vim`, `python3`, `perl`, `env`, `awk`)
- `Fail` severity for any match

Acceptance: Scanner emits `scan:sudoers_risk` critical alert when vulnerable config present.

**P0.3: Incident mode toggle**

Files: `src/config.rs`, `src/main.rs` wiring

- `response.incident_mode = true|false`
- When enabled: proxy keys locked, clawsudo deny-all except `clawtower` commands, dedup windows shortened to 2s for Critical, aggregator rate limits removed for Critical
- Activatable via admin socket or config
- Slack notification on activate/deactivate

Acceptance: Single toggle transitions system into deterministic containment mode.

**P0.4: Tiered default profiles**

Files: `profiles/startup.toml`, `profiles/production.toml`, `profiles/enterprise-strict.toml`

- Three curated config bundles as config overlays using existing `config.d/` merge system
- `startup` — permissive, developer-friendly, alert-only
- `production` — balanced, clawsudo enforced, netpolicy allowlist, DLP enabled
- `enterprise-strict` — deny-first everything, incident mode pre-armed, shortest dedup windows
- `clawtower setup --profile enterprise-strict` applies the profile

---

### Phase 1 — Agent Abstraction + Supply Chain (Weeks 2-4)

Makes ClawTower agent-agnostic and builds supply chain defense. Coupled because the agent profile system defines where skills live.

**P1.1: Agent Profile system**

Files: new `src/agent_profile.rs`, `src/config.rs`, `src/cognitive.rs`, `src/sentinel.rs`

- Load profiles from `/etc/clawtower/agents.d/*.toml`
- Refactor `cognitive.rs` to read identity files from profiles
- Refactor `sentinel.rs` to auto-generate watch paths from profiles
- Remove `OpenClawConfig` from `config.rs` — migrate to `agents.d/openclaw.toml`
- Ship curated profiles: `openclaw.toml`, `claude-code.toml`, `devin.toml`, `cursor-agent.toml`, `generic.toml`
- CLI: `clawtower agent list`, `clawtower agent add <name>`

Acceptance: `agents.d/openclaw.toml` produces identical monitoring behavior to current hardcoded config. At least 3 agent profiles shipped and documented.

**P1.2: Skill intake scanner**

Files: `src/sentinel.rs`, `src/barnacle.rs`

- Sentinel triggers intake scan on new files in `agent.skill_paths` directories
- Parse manifest, static scan against BarnacleDefense DBs, permission check against profile allowlist
- Hash skill directory into append-only skill manifest ledger
- Quarantine action for blocked skills (`/var/lib/clawtower/quarantine/`)
- New alert source: `supply_chain` with categories `skill_intake_pass`, `skill_intake_warn`, `skill_intake_block`

Acceptance: ClawHavoc-style skill with base64 installer in SKILL.md triggers Critical alert at install time.

**P1.3: Cognitive social-engineering detector**

Files: `src/behavior.rs` or policy YAML

- Patterns for base64-piped installer chains, external script fetch instructions, password-protected archive instructions, known paste/snippet service references
- Applied to command stream AND content of sentinel-watched files

Acceptance: ClawHavoc prerequisite deception patterns trigger deterministic warning/critical signals.

**P1.4: Per-skill behavioral attribution**

Files: `src/auditd.rs`, `src/behavior.rs`, `src/alerts.rs`

- Track process tree parentage for monitored UIDs
- Walk process tree to determine originating skill directory
- Annotate alerts with `skill_name` field when attributable

Acceptance: Alerts from skill-initiated processes include skill name attribution.

---

### Phase 2 — Agent Identity & Capability Envelope (Weeks 4-8)

Treats agents as managed identities with least-privilege enforcement.

**P2.1: Agent Identity Registry**

Files: new `src/identity.rs`, `src/api.rs`

- Runtime identity record per loaded agent profile: `agent_id`, `trust_level`, `risk_score`, `lifecycle_state`
- API endpoints: `GET /api/agents`, `GET /api/agents/{id}`, `PATCH /api/agents/{id}`
- Every alert tagged with `agent_id`
- Identity state changes generate alerts and audit chain entries

**P2.2: Capability envelope**

Files: new `src/capability.rs`, `src/aggregator.rs`

- Envelope defined in agent profile TOML
- Capability matcher in the aggregator pipeline
- Alerts within envelope: downgrade (or suppress in permissive mode)
- Alerts outside envelope: upgrade to `envelope_violation` category

**P2.3: Credential scoping + ephemeral keys**

Files: `src/proxy.rs`, `src/config.rs`

- Proxy key mappings gain `ttl` and `scope` fields
- Auto-revoke keys when risk score exceeds threshold or trust level drops
- Every key issuance and revocation recorded in audit chain

**P2.4: Signed IOC bundle lifecycle**

Files: `src/update.rs`, `src/barnacle.rs`

- IOC databases gain version header + Ed25519 signature
- Each alert records IOC bundle version
- Keep previous 3 bundles for rollback

**P2.5: Dynamic authorization hooks**

Files: new `src/dynamic_auth.rs`, policy YAML

- Risk score + trust level + requested action = allow/deny/require_approval
- YAML policy expression

Acceptance: Every alert carries `agent_id` and envelope violation status. Proxy keys expire and auto-revoke. IOC bundles signed and versioned. Dynamic auth rules can deny actions based on risk score.

---

### Phase 3 — Enterprise Integration & SaaS (Weeks 8-14)

Plugs ClawTower into enterprise security ecosystems. Cloud management plane comes online.

**P3.1: Export pipeline**

Files: new `src/export.rs`, `src/config.rs`, `src/aggregator.rs`

- Syslog CEF format (UDP/TCP/TLS)
- Generic JSON webhook
- File export with rotation (for Splunk forwarder / Fluentd)
- All exports include `agent_id`, `skill_name`, `envelope_violation`, `ioc_version`

**P3.2: Compliance report generation**

Files: new `src/compliance.rs`, CLI integration

- `clawtower compliance-report --framework soc2 --period 30d --output report.pdf`
- Maps alert categories to SOC 2, NIST 800-53, CIS Controls, ISO 27001
- JSON export variant for programmatic consumption

**P3.3: Cloud management plane MVP**

- Agent registration via Ed25519 keypair + mTLS gRPC
- Fleet dashboard: all agents, trust levels, risk scores, recent alerts
- Policy push: update profiles, envelopes, IOC bundles centrally
- Org-level skill allowlist: approve skills centrally, enforce locally
- Skill reputation: skill hash triggers alerts on 3+ agents = auto-flag fleet-wide

**P3.4: Buyer-facing artifacts**

- Threat model one-pager (PDF)
- Security architecture diagram
- Pentest delta dashboard (v4 -> v8 -> current)
- Hardening checklist for SOC/IT admins
- Control mapping matrix (CSV/PDF)

Acceptance: Alerts appear in customer Splunk/ELK within 5 seconds. Compliance report generates valid SOC 2 mapping. Cloud policy update enforced across 3+ agents within 60 seconds. Skill blocked on one agent auto-flags fleet within 5 minutes.

---

## Summary Timeline

```
Week 1          Weeks 2-4           Weeks 4-8            Weeks 8-14
+----------+   +---------------+   +---------------+   +-------------------+
| PHASE 0  |   | PHASE 1       |   | PHASE 2       |   | PHASE 3           |
|          |   |               |   |               |   |                   |
| clawsudo |   | Agent profiles|   | Identity      |   | SIEM export       |
| hardening|   | Skill intake  |   | registry      |   | Compliance reports|
| sudoers  |   | Social-eng    |   | Capability    |   | Cloud mgmt plane  |
| scanner  |   | detector      |   | envelope      |   | Fleet skill intel |
| Incident |   | Per-skill     |   | Ephemeral     |   | Buyer artifacts   |
| mode     |   | attribution   |   | creds         |   |                   |
| Profiles |   |               |   | Signed IOCs   |   |                   |
|          |   |               |   | Dynamic auth  |   |                   |
+----------+   +---------------+   +---------------+   +-------------------+
  Fixes the       Makes it            Makes it            Plugs into
  front door      agent-agnostic      enterprise-grade    their stack
```

---

## KPIs

| KPI | Target | Phase |
|-----|--------|-------|
| Privilege abuse prevention rate (Red Lobster derived) | >95% denied | P0 |
| Skill intake scan coverage | 100% of new skill installs scanned | P1 |
| Alert-to-agent attribution rate | >99% of alerts carry `agent_id` | P2 |
| Mean time to IOC update | <24h signed rollout | P2 |
| SIEM ingestion latency | <5s from detection to SIEM | P3 |
| Fleet policy propagation time | <60s cloud-to-agent | P3 |
| False-positive rate on enterprise-strict | <5% for approved workflows | All |

---

## Risks and Mitigations

- **Risk:** Strict defaults break existing ops workflows.
  **Mitigation:** Profile-based rollout + migration docs + dry-run mode.

- **Risk:** Increased detection noise from new social-engineering patterns.
  **Mitigation:** Shadow mode + dedup tuning + staged severity escalation.

- **Risk:** Identity model adds complexity to runtime pipeline.
  **Mitigation:** Parity-first adapter pattern (same approach as detect/runtime abstraction plan).

- **Risk:** SaaS management plane introduces new trust dependency.
  **Mitigation:** Agent autonomy preserved — full local operation if cloud unreachable. Cloud is for management, never enforcement.

- **Risk:** Agent profile abstraction breaks existing OpenClaw deployments.
  **Mitigation:** Auto-migration tool converts existing `[openclaw]` config section to `agents.d/openclaw.toml`. Backward-compat shim for one release cycle.

---

## Definition of "Enterprise-Ready"

ClawTower is enterprise-ready when all are true:

1. Known privileged abuse chains are blocked by default in enterprise-strict profile.
2. Each agent is represented and governed as a first-class identity with capability envelope.
3. Marketplace/plugin supply-chain risks are controlled at both install-time and runtime.
4. Security outcomes are demonstrable through SIEM integration and exportable compliance evidence.
5. Fleet-wide management and policy enforcement operates from a central SaaS plane.
6. Agent-agnostic — works with any AI agent framework via declarative profiles.
7. Adversarial regressions (Red Lobster suite) are part of CI and release gates.