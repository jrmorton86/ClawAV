# ClawTower Enterprise Hardening Roadmap (Post-ClawHavoc + Enterprise Restrictions)

**Date:** 2026-02-18  
**Branch:** `security-remediation`  
**Audience:** Engineering, Security, Product, Enterprise GTM

## Why this plan exists

New threat intel over the last 24 hours shifts the bar for enterprise adoption:

1. **Enterprise restrictions on OpenClaw** are now being reported by major outlets and secondary sources.
2. **ClawHavoc marketplace poisoning** expanded from initial hundreds to much larger historical totals (up to 1,184 in one report).
3. **Identity-first security** for agents (treating agents as privileged identities) is becoming a dominant enterprise expectation.

ClawTower already has strong runtime coverage (auditd + sentinel + behavior + policies + BarnacleDefense), but current pentest artifacts show a hard gap in privileged abuse pathways and formal enterprise controls.

---

## Source confidence snapshot

### High confidence (primary/first-party or direct technical writeups)

- OpenClaw discussion on malicious skills incident and mitigation direction:
  - https://github.com/openclaw/openclaw/discussions/7606
- Koi ClawHavoc technical report + IOCs + attack chains:
  - https://www.koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting
- Antiy ClawHavoc large-scale analysis (includes 1,184 historical stat):
  - https://www.antiy.net/p/clawhavoc-analysis-of-large-scale-poisoning-campaign-targeting-the-openclaw-skill-market-for-ai-agents/

### Medium confidence (secondary reporting / aggregators)

- CyberArk “agents as identities” controls (identity-first, discovery, least privilege, lifecycle):
  - https://futurecio.tech/cyberark-unveils-identity-security-solution-to-secure-ai-agents-at-scale/
  - https://securityreviewmag.com/?p=28986

### Low confidence / blocked extraction

- WIRED page could not be directly scraped due anti-bot/ad redirects in this environment.
- Treat enterprise-ban claims as **credible but not fully verified** until a clean source copy is archived internally.

---

## Current ClawTower baseline (what already maps well)

## Existing strengths (already in code)

- **Aggregator choke point preserved** (`src/main.rs` + `aggregator.rs`) — alert fanout centralization.
- **Runtime prevention + detection layers**:
  - `auditd` syscall parsing (`src/auditd.rs`) with connect/sendto monitoring.
  - hardcoded behavior engine (`src/behavior.rs`) with LD_PRELOAD and exfil patterns.
  - YAML policy detection (`src/policy.rs`, `policies/default.yaml`).
  - BarnacleDefense vendor pattern matching (`src/barnacle.rs`) including supply-chain IOC DB.
  - sentinel file integrity + quarantine/restore (`src/sentinel.rs`, `src/config.rs` defaults).
- **Credential handling primitives**:
  - Proxy with virtual-to-real key mapping + DLP (`src/proxy.rs`).
- **Enterprise foundations**:
  - API auth token support (`src/api.rs`), hash-chained audit log, admin socket auth.

## Critical gaps to close for enterprise trust

1. **Privileged command governance gap**
   - Red Lobster v8 shows direct NOPASSWD sudo abuse path remains critical.
   - `policies/clawsudo.yaml` still contains broad `allow-file-ops` and `allow-systemctl` that are too permissive for enterprise hardening profiles.

2. **Marketplace supply-chain controls are detection-heavy, not policy-enforced-by-default**
   - Supply-chain IOC matching exists but deployment/rollback and policy binding are not yet opinionated for “marketplace hostile by default”.

3. **Agent identity lifecycle controls are not explicit first-class objects**
   - Controls exist piecemeal (credentials watch, auth files watch, response engine), but no unifying “agent identity registry + risk state + scoped privilege token” model.

4. **Enterprise proof artifacts are weakly packaged**
   - Strong engineering work exists, but procurement-ready outputs (control matrix, SLAs, assurance evidence bundles) are not yet centralized.

---

## Strategic response model

Adopt three simultaneous tracks:

1. **Containment-first hardening** (close known exploit paths immediately).
2. **Identity-first architecture** (agents are privileged principals with lifecycle governance).
3. **Assurance-first productization** (measurable controls, evidence, and compliance mapping).

---

## Priority roadmap

## P0 (0–7 days): Stop known high-risk abuse

### P0.1 Harden clawsudo policy defaults

**Files:** `policies/clawsudo.yaml`, `src/bin/clawsudo.rs` tests  
**Actions:**
- Replace broad `allow-file-ops` with explicit safe read-only allowlist.
- Restrict `allow-systemctl` to read-only/status operations by default profile.
- Introduce explicit deny entries for:
  - `find -exec`, `sed e`, `tee` to sensitive paths, `chmod +s`, sudoers writes.
- Ship a strict enterprise profile variant (`policies/clawsudo-enterprise.yaml`) and make it documented default for business deployments.

**Acceptance:**
- Red Lobster v8 flag 15: severe reduction in successful direct privilege abuse.
- Red Lobster v8 flag 16: 100% deny on previously identified 5 holes.

### P0.2 Add scanner for risky sudoers/NOPASSWD patterns

**Files:** `src/scanner.rs`  
**Actions:**
- Add `scan_sudoers_risk()` to detect NOPASSWD on GTFOBins-capable binaries.
- Severity should be `Fail` for root-equivalent entries (`find`, `sed`, `tee`, `cp`, `mv`, `chmod`, unrestricted `systemctl`).

**Acceptance:**
- Scanner emits `scan:sudoers_risk` critical alert when vulnerable config present.

### P0.3 Enterprise incident mode toggle

**Files:** `src/config.rs`, `config.toml` docs, `src/main.rs` wiring  
**Actions:**
- Add `response.incident_mode = true|false` with effects:
  - lock proxy keys,
  - force clawsudo deny-all except break-glass commands,
  - increase alert verbosity and shorter dedup windows for criticals.

**Acceptance:**
- Single config toggle transitions system into deterministic containment mode.

---

## P1 (1–3 weeks): Agent identity-first controls

### P1.1 Introduce Agent Identity Registry (AIR)

**New module proposal:** `src/identity.rs`  
**Data model:**
- `agent_id`, owner, environment, auth surfaces, allowed capabilities, trust level, last attestation, risk score.

**Integrations:**
- `response` engine decisions scoped by `agent_id`.
- `proxy` key mapping bound to `agent_id` and policy scope.
- `api` endpoints for identity state (`/api/identities`, `/api/identities/{id}`).

**Acceptance:**
- Every high-risk event can be attributed to an identity object (not only UID/process string).

### P1.2 Capability-scoped ephemeral credentials

**Files:** `src/proxy.rs`, config schema  
**Actions:**
- Support time-bounded, scope-bounded virtual keys (JIT-like behavior).
- Enforce “zero standing privilege” mode for external API access.
- Add automatic key revocation on severe anomalies.

**Acceptance:**
- Proxy can deny stale/out-of-scope keys even if long-lived real secret remains valid.

### P1.3 Dynamic authorization hooks

**Files:** `src/response.rs`, `src/correlator.rs`, API  
**Actions:**
- Add policy decision point that considers risk score + requested action + target asset class.
- For high-risk combinations, require explicit human approval or deny.

**Acceptance:**
- Demonstrable policy: $\text{high risk} \land \text{privileged action} \Rightarrow \text{deny or step-up approval}$.

---

## P2 (3–6 weeks): Marketplace supply-chain defense-in-depth

### P2.1 Skill trust pipeline (pre-install + runtime)

**Files:** `src/barnacle.rs`, `src/sentinel.rs`, `src/policy.rs`  
**Actions:**
- Add dedicated skill/extension trust policy class:
  - unsigned skill,
  - suspicious prerequisite instructions,
  - password-protected archive instructions,
  - external script execution bootstrap (glot/rentry/raw HTTP).
- Tie these matches to enforcement recommendations (block/quarantine/approval).

**Acceptance:**
- Installation of known malicious skill archetypes produces immediate critical + containment action.

### P2.2 IOC lifecycle automation

**Files:** `src/update.rs`, vendor DB tooling  
**Actions:**
- Signed IOC bundle ingestion with rollback.
- Track IOC bundle version in alerts and API for auditability.

**Acceptance:**
- Can prove which IOC version made each decision.

### P2.3 “Cognitive social-engineering” detector pack

**Files:** `src/behavior.rs`, policy YAML  
**Actions:**
- Add patterns for deceptive docs/install strings:
  - “copy/paste this prerequisite command”,
  - base64 piped installer chains,
  - password ZIP install instructions.
- Apply to both command stream and watched documentation files.

**Acceptance:**
- ClawHavoc-like prerequisite deception triggers deterministic warning/critical signals.

---

## P3 (6–10 weeks): Enterprise assurance & adoption package

### P3.1 Control matrix and evidence API

**Docs + API additions:**
- Map controls to MITRE ATT&CK + enterprise frameworks (NIST CSF / ISO 27001 control families).
- Export evidence bundle:
  - policy hash/version,
  - scanner status snapshot,
  - latest audit-chain integrity proof,
  - key response events.

### P3.2 Secure defaults profiles

Ship 3 curated profiles:
- `startup` (developer-friendly)
- `production` (balanced)
- `enterprise-strict` (deny-first + JIT credentials + explicit approvals)

### P3.3 Buyer-facing artifacts

- Threat model one-pager
- Security architecture diagram (runtime + identity controls)
- Pentest delta dashboard (v4/v8 → current)
- Hardening checklist for SOC/IT admins

---

## Implementation sequencing (recommended)

1. **Fix privileged abuse first (P0)** — this is the largest trust blocker.
2. **Land identity primitives (P1)** — aligns with market direction and enterprise IAM expectations.
3. **Deepen marketplace defenses (P2)** — direct response to ClawHavoc class.
4. **Package assurance evidence (P3)** — converts strong engineering into procurement confidence.

---

## KPIs to track

- **Privilege abuse prevention rate** (Red Lobster v8-derived): target >95% denied/contained.
- **Mean time to IOC protection update**: target <24h signed rollout.
- **Agent identity coverage**: % alerts attributed to concrete `agent_id` object.
- **False-positive rate on strict profile**: keep <5% for approved enterprise workflows.
- **Auditability score**: % critical decisions with complete evidence chain.

---

## Immediate next sprint backlog (ready to implement)

1. `P0-001` Tighten `policies/clawsudo.yaml` (remove broad `allow-file-ops`).
2. `P0-002` Add `scan_sudoers_risk()` in `src/scanner.rs`.
3. `P0-003` Add config flag + wiring for incident mode.
4. `P0-004` Add regression tests for v8 holes (flag 15/16 reproductions).
5. `P1-001` Create `identity.rs` skeleton + API read endpoint.

---

## Risks and mitigations

- **Risk:** Strict defaults break existing ops workflows.  
  **Mitigation:** profile-based rollout + migration docs + dry-run mode.

- **Risk:** Increased detection noise from new social-engineering patterns.  
  **Mitigation:** shadow mode + dedup tuning + staged severity escalation.

- **Risk:** Identity model adds complexity to runtime pipeline.  
  **Mitigation:** parity-first adapter pattern (same approach as detect/runtime abstraction plan).

---

## Definition of “enterprise-ready” for ClawTower

ClawTower is enterprise-ready when all are true:

1. Known privileged abuse chains are blocked by default in enterprise profile.
2. Each agent is represented and governed as a first-class identity.
3. Marketplace/plugin supply-chain risks are pre-install and runtime controlled.
4. Security outcomes are demonstrable through exportable evidence and repeatable tests.
5. Hidden-test style adversarial regressions are part of CI and release gates.
