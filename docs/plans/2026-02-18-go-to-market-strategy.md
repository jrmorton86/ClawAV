# ClawTower Go-to-Market Strategy

**INTERNAL — PRAXIS AI + JR MORTON — NOT FOR PUBLIC DISTRIBUTION**

---

## Executive Summary

ClawTower is the first OS-level security watchdog purpose-built for AI agents. No competing product exists in this category. The strategy is to open-source under AGPL-3.0 with a Contributor License Agreement (CLA) to:

1. **Flood the space** — establish ClawTower as the default answer to "how do I secure my AI agent deployment"
2. **Lock in community** — AGPL copyleft prevents competitors from forking without open-sourcing their modifications
3. **Retain commercial control** — CLA enables dual-licensing; exclusive commercial services through Praxis AI
4. **Preserve optionality** — if open source doesn't achieve critical mass, pivot to closed-source Praxis-internal product

**IP ownership remains with JR Morton.** Praxis receives an exclusive commercial license for services, support, and enterprise distribution. Equity negotiation is deferred until community traction validates the market.

---

## Product Positioning

### Category Creation: "AI Agent Security Watchdog"

No established category exists. Competitors are either:
- **Generic HIDS** (OSSEC, Wazuh) — not AI-agent-aware, no behavioral threat model for autonomous agents
- **Container security** (Falco, Sysdig) — runtime detection but no agent-specific policies, no "swallowed key" tamper resistance
- **AI safety tools** (Guardrails, NeMo) — prompt-level, not OS-level; can be bypassed by the agent itself

ClawTower is the only product that:
- Monitors at the **kernel level** (auditd, inotify, eBPF) — the agent cannot evade or disable it
- Has a **behavioral threat model** specifically for AI agents (data exfil, credential theft, persistence, container escape)
- Implements the **"swallowed key" pattern** — the agent it protects cannot modify, stop, or reconfigure ClawTower
- Includes **clawsudo** — a policy-enforced sudo gatekeeper that prevents privilege escalation

### Target Audience

| Segment | Pain Point | Message |
|---------|-----------|---------|
| **AI/ML Engineers** | "My agent has shell access and I have no idea what it's doing" | Real-time monitoring dashboard, Slack alerts |
| **DevOps/SRE** | "How do I give an AI agent access without giving it the keys to the kingdom?" | clawsudo policy enforcement, file integrity monitoring |
| **Security Teams** | "We need to audit what autonomous agents are doing on our infrastructure" | Hash-chained audit logs, 30+ security scanners, MITRE ATT&CK-aligned detection |
| **Startups deploying AI agents** | "We need security for compliance but don't have a security team" | One-line install, sensible defaults, OpenClaw integration |

### Key Differentiators

1. **Tamper-proof by design** — immutable binaries, chattr protection, the agent cannot disable its own watchdog
2. **270+ behavioral detection patterns** — purpose-built for AI agent threat models
3. **Drop-in for OpenClaw** — pre-configured monitoring for the most popular AI agent framework
4. **Defense-in-depth** — auditd + inotify + behavioral + policy + network + scanner layers
5. **Battle-tested** — Red Lobster pentest suite with 35+ attack vectors across 17 flags

---

## Licensing Architecture

### AGPL-3.0 + CLA on GitHub

```
┌─────────────────────────────────────────────────────┐
│  ClawTower Source Code                               │
│  License: AGPL-3.0-or-later                         │
│  Copyright (c) 2025-2026 JR Morton                  │
│                                                      │
│  ┌──────────────┐    ┌───────────────────────┐      │
│  │ Contributors │───▶│ CLA (assign rights)   │      │
│  └──────────────┘    └───────────┬───────────┘      │
│                                  │                   │
│                    ┌─────────────▼─────────────┐    │
│                    │ Dual Licensing Enabled     │    │
│                    │                            │    │
│                    │  AGPL: Community/free      │    │
│                    │  Commercial: Praxis AI     │    │
│                    └────────────────────────────┘    │
└─────────────────────────────────────────────────────┘
```

**Why AGPL-3.0:**
- **Real OSI-approved open source** — engineers trust it, unlike BSL/SSPL/Elastic which are "source-available"
- **Network copyleft clause** — if a cloud provider hosts ClawTower as a service, they must open-source their modifications (this is why MongoDB moved to SSPL — AGPL already covers this use case)
- **Prevents silent forks** — competitors can fork, but must release all modifications under AGPL
- **CLA enables dual-licensing** — because all contributors assign rights, the copyright holder (JR Morton) can offer a separate commercial license that doesn't have AGPL obligations

**Why CLA (Contributor License Agreement):**
- Without CLA, each contributor owns their copyright and you can't dual-license
- CLA grants JR Morton (and by extension, Praxis via commercial license) the right to relicense contributions
- Industry standard: used by Apache Foundation, Google, Meta, GitLab
- Use the [Apache Individual CLA](https://www.apache.org/licenses/icla.pdf) as template — well-understood, contributor-friendly

**What this means practically:**
- Anyone can use ClawTower for free under AGPL terms
- Enterprises that don't want AGPL obligations (can't open-source their deployment configs, custom policies, etc.) buy a commercial license from Praxis
- Competitors can't just fork and close-source it
- Cloud providers can't offer "ClawTower-as-a-Service" without open-sourcing their wrapper

---

## Praxis AI Partnership Structure

### Current State: Consulting Services

- JR Morton provides consulting services to Praxis AI
- ClawTower IP is **not a work product** — it is independently created and owned by JR Morton
- Praxis receives an exclusive right to provide commercial services (support, enterprise licenses, managed deployment) around ClawTower

### Commercial License Terms (Proposed)

| Term | Detail |
|------|--------|
| **Licensor** | JR Morton (sole copyright holder) |
| **Exclusive Licensee** | Praxis AI, Inc. |
| **Scope** | Commercial sublicensing, enterprise support, managed services, training |
| **Territory** | Worldwide |
| **Duration** | 3 years initial, auto-renew |
| **Revenue share** | [To be negotiated — 15-30% of commercial revenue to licensor] |
| **Equity trigger** | If ARR from ClawTower exceeds $[X], renegotiate for equity position |
| **Termination** | If Praxis fails to commercialize within 18 months, exclusive rights revert to non-exclusive |
| **Attribution** | All commercial distributions must credit "Created by JR Morton" |

### Equity Negotiation Framework

The equity conversation is deferred until market validation, but the commercial license should include **pre-negotiated triggers**:

- **Trigger 1: GitHub stars > 5,000** — Validates market demand. Begin equity discussion.
- **Trigger 2: First paying enterprise customer** — Validates commercial viability. Formalize equity offer.
- **Trigger 3: ARR > $500K** — Validates business model. Equity must be resolved or exclusive license terminates.

This protects both sides: Praxis doesn't give equity for an unproven product, and JR doesn't give away commercial rights to a product that Praxis profits from without fair compensation.

---

## Go-to-Market Phases (Viral Cadence)

> **Operating assumption:** This is going viral. Timelines are compressed to hours/days, not weeks/months. Every phase overlaps. Move at the speed of attention.

### Phase 1: Launch Day (Hours 0-24) — "Detonate"

**Goal:** Maximum first-impression impact. Own the narrative before anyone else can frame it.

**Hour 0 — Push:**
- [ ] Push to GitHub under AGPL-3.0 with CLA (repo must be pristine: README, LICENSE, CONTRIBUTING, CODE_OF_CONDUCT all in place)
- [ ] GitHub repo description, topics, and social preview image set

**Hours 0-2 — Ignite:**
- [ ] Submit to Hacker News with launch post: "Your AI Agent Has Root Access. Now What?"
- [ ] Post on X/Twitter with 60-second demo clip (TUI dashboard catching a live threat)
- [ ] Reddit simultaneous drop: r/netsec, r/MachineLearning, r/selfhosted, r/rust
- [ ] Cross-post to OpenClaw community channels (Discord, forums)

**Hours 2-12 — Feed the fire:**
- [ ] Monitor HN/Reddit comments — respond to every technical question within 30 minutes
- [ ] Engage with quote-tweets and reposts on X — be present, not promotional
- [ ] DM 10-15 influential AI/security accounts with personalized "thought you'd find this interesting"
- [ ] If HN front page: prepare follow-up "Ask HN" or Show HN with technical deep-dive

**Hours 12-24 — Sustain:**
- [ ] Publish to awesome-security, awesome-ai-agents, awesome-rust lists (PRs ready in advance)
- [ ] Second-wave X post: different angle (e.g., the Red Lobster pentest results, or a specific attack being caught)
- [ ] Capture and share early community reactions/quotes

**Messaging:** "The AI agent security problem is solved. ClawTower monitors your agent at the OS level — and the agent can't turn it off."

**Key metric:** GitHub stars in first 24 hours. Target: 500+. Stretch: 1,000+

### Phase 2: First Week (Days 1-7) — "Convert Attention to Community"

**Goal:** Turn viral traffic into contributors and adopters before attention decays.

**Day 1-2:**
- [ ] Create 10+ "good first issue" labels — these must be real, meaningful, completable in <2 hours
- [ ] CLA Assistant bot live on repo (contributors hit zero friction)
- [ ] Discord server live with channels: #general, #support, #contributing, #security-research
- [ ] Pin a "Welcome new contributors" discussion on GitHub with architecture overview

**Day 2-4:**
- [ ] Publish launch blog post with full technical deep-dive (self-hosted or dev.to/Medium)
- [ ] 2-minute polished demo video: install ClawTower → deploy AI agent → watch it detect threats in real-time
- [ ] Triage and respond to every issue/PR within 4 hours — speed signals a healthy project
- [ ] Begin daily changelog/update posts on X showing momentum ("Day 3: 12 PRs merged, 3 new detection rules from community")

**Day 4-7:**
- [ ] Ship at least one community-contributed feature or fix (visible proof the project accepts contributions)
- [ ] Integration guide for at least one AI agent framework beyond OpenClaw
- [ ] Identify and personally reach out to top 3-5 early contributors for deeper engagement
- [ ] Weekly security advisory or threat intel post (establish the cadence immediately)

**Key metric:** First external PR merged. Target: within 72 hours. Contributors by day 7: 10+

### Phase 3: First Month (Days 7-30) — "Establish the Standard"

**Goal:** Solidify ClawTower as the default answer. Begin commercial conversations.

**Week 2:**
- [ ] Plugin/extension system for community-contributed detection rules (lower the barrier)
- [ ] Conference talk proposals submitted: DEF CON AI Village, BSides, KubeCon, AI Engineer Summit
- [ ] Integration guides for 3+ AI agent frameworks
- [ ] Reach out to security-focused YouTubers/streamers for coverage

**Week 3-4:**
- [ ] First enterprise inbound inquiry → warm intro to Praxis for commercial conversation
- [ ] Begin compliance documentation (SOC2 mapping, ISO 27001 evidence generation guide)
- [ ] Praxis commercial license agreement finalized with equity triggers
- [ ] Monthly community call / office hours (establish recurring cadence)

**Commercial-only features (not in AGPL repo) — begin scoping:**
- Managed ClawTower SaaS (Praxis-hosted)
- Multi-agent fleet dashboard (central monitoring for N agents)
- Compliance reporting (SOC2, ISO 27001 evidence generation)
- Priority support SLA
- Custom policy development
- Incident response consulting

**Key metric:** Stars: 2,000+. Contributors: 20+. First enterprise conversation.

### Phase 4: Months 2-6 — "Monetize and Formalize"

**Goal:** First paying customers through Praxis. Evaluate foundation path.

- [ ] First 3 paying enterprise customers. Target ARR: $100K+
- [ ] Evaluate foundation model (Linux Foundation / CNCF sandbox) based on traction
- [ ] If foundation path: transfer trademark (not copyright), JR Morton retains copyright + CLA rights
- [ ] Foundation handles governance, roadmap voting, contributor management
- [ ] Praxis remains exclusive commercial licensee

**Foundation trigger:** 2,000+ stars, 20+ contributors, 3+ enterprise customers.

---

## Contingency: Closed-Source Pivot

**Trigger:** Viral launch fizzles — fails to sustain momentum past week 2 (< 500 stars, < 5 contributors, no enterprise interest by day 30).

**Pivot plan:**
1. Archive GitHub repo (don't delete — maintains credibility)
2. Continue development as Praxis-internal product
3. Offer as proprietary SaaS or on-prem enterprise software
4. Existing AGPL users can continue using the last open-source version (AGPL is irrevocable for published code)
5. New development is proprietary

**Why this works:** AGPL + CLA means you always have the right to change licensing for new code. Existing published code remains AGPL forever, but new features and improvements can be proprietary.

---

## Competitive Landscape

### AI Agent Ecosystem (ClawTower's Addressable Market)

Every agent in this landscape is a potential ClawTower deployment. The more agents that exist, the larger the market for runtime security.

| Category | Players | ClawTower Relevance |
|----------|---------|-------------------|
| **Open-source self-hosted agents** | OpenClaw, Nanobot, SuperAGI, memU, Goose | Primary market — self-hosted means the operator owns security. No vendor safety net. |
| **Serverless/cloud agent runtimes** | Moltworker (Cloudflare Workers) | Lower priority — cloud provider handles OS-level security. ClawTower less relevant unless self-hosted. |
| **Developer SDKs/frameworks** | Claude Agent SDK, Open Code SDK, LangChain, AgentGPT | Orthogonal — these are prompt/API-level tools. They don't do OS-level monitoring. Users of any SDK still need ClawTower. |
| **Enterprise managed agents** | Microsoft Copilot, Knolli.ai, Devin, Adept | Low priority — enterprise vendors bundle their own security. But enterprises running *any* open-source agent on their own infra are prime targets. |
| **Coding agents** | Claude Code, Codex CLI, Aider, Continue, SWE-agent | High-value niche — these agents have direct filesystem and shell access. Exactly the threat model ClawTower was built for. |

**Key takeaway:** ClawTower's market grows with every new AI agent. Agent-agnostic positioning is critical — do not tie the brand to OpenClaw alone.

### Direct Security Overlap: NanoClaw

NanoClaw is the only product that overlaps with ClawTower's positioning. It markets itself as the "security-focused" OpenClaw alternative, using Docker/container isolation to sandbox the agent.

**Why NanoClaw is not a substitute for ClawTower:**

| Dimension | NanoClaw (Container Isolation) | ClawTower (Runtime Monitoring) |
|-----------|-------------------------------|-------------------------------|
| **Philosophy** | Prevention — sandbox the agent so it *can't* cause damage | Detection + response — watch what the agent *does* and alert in real-time |
| **Failure mode** | Container escape = total compromise with zero visibility | Agent has access but every action is monitored, logged, and auditable |
| **Forensics** | None — if the sandbox holds, nothing to see; if it breaks, nothing was logged | Hash-chained tamper-evident audit trail of every syscall and file change |
| **Policy granularity** | Binary — inside the container or outside | 270+ behavioral patterns, per-command sudo evaluation, file-level protection policies |
| **Tamper resistance** | Agent can potentially modify container config if it has Docker access | Swallowed-key pattern — agent cannot modify, stop, or reconfigure ClawTower |
| **Agent compatibility** | OpenClaw only | Any agent, any framework |
| **Detection categories** | None (prevention-only) | Data exfil, privilege escalation, persistence, recon, side-channel, container escape |

**Positioning against NanoClaw:** "Containers are a wall. ClawTower is a camera + alarm system. You want both." ClawTower *inside* a NanoClaw container is the strongest possible setup. Frame it as complementary, not competitive.

**Messaging risk:** If NanoClaw gains adoption, users may perceive container isolation as "good enough" security. Counter this with concrete examples of threats containers don't catch: prompt injection causing data exfil through allowed network paths, credential theft from environment variables, or an agent subtly modifying its own identity files. These all happen *inside* the sandbox.

### Adjacent Security Tools (Not Competitors)

These tools operate at different layers. ClawTower complements all of them.

| Tool | Layer | Relationship to ClawTower |
|------|-------|--------------------------|
| **OSSEC / Wazuh** | Generic HIDS | No AI-agent behavioral model, no swallowed-key pattern. ClawTower is purpose-built; these are general-purpose. |
| **Falco / Sysdig** | Container runtime detection | ClawTower *ingests* Falco alerts as a data source. Complementary, not competitive. |
| **Guardrails / NeMo** | Prompt-level AI safety | Prompt-level, not OS-level. Agent can bypass prompt guards via injection. Orthogonal. |
| **VirusTotal / marketplace scanners** | Static analysis, pre-install | Catches known malware signatures. ClawTower catches unknown/novel threats at runtime. Complementary. |
| **AppArmor / SELinux** | Kernel MAC | Mandatory access control. ClawTower *monitors* AppArmor state and can use it as enforcement. Complementary. |

---

## Competitive Moat (Why This Is Defensible)

1. **First mover in an empty category** — there is no "AI agent security watchdog" market today. ClawTower defines it.
2. **Agent-agnostic by design** — works with OpenClaw, Claude Code, Devin, LangChain agents, custom agents — anyone on Linux. Not locked to one ecosystem.
3. **AGPL prevents hostile forks** — competitors must open-source modifications, so they can't out-feature you in secret.
4. **Deep Linux integration** — 10K+ lines of Rust interfacing with auditd, inotify, eBPF, chattr, AppArmor. Non-trivial to replicate.
5. **Battle-tested pentest suite** — Red Lobster v5-v8, 35+ attack vectors. This is years of adversarial testing baked in.
6. **Complementary to everything** — ClawTower sits below containers (NanoClaw), below prompt guards (Guardrails), below marketplace scanners (VirusTotal). It doesn't compete with any layer — it fills the gap none of them cover.
7. **Community lock-in** — once engineers deploy ClawTower and write custom policies, switching costs are high.

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| NanoClaw positioned as "good enough" security | Medium | High | Frame as complementary ("wall + camera"), publish concrete examples of threats containers miss, offer integration guide |
| Cloud provider forks ClawTower | Medium | High | AGPL forces open-sourcing; CLA enables commercial enforcement |
| OpenClaw builds native runtime security | Low | Critical | Deepen integration, contribute upstream, make ClawTower complementary not competitive |
| Generic HIDS (Wazuh/OSSEC) adds AI-agent features | Medium | Medium | Move faster, own the narrative, community > features |
| Market fragments across agent-specific security tools | Low | Medium | Agent-agnostic positioning means ClawTower wins regardless of which agent "wins" |
| No community adoption | Medium | High | Closed-source pivot to Praxis internal |
| Praxis can't commercialize | Medium | Medium | Revert to non-exclusive license, find alternative partner |
| Contributor refuses CLA | Low | Low | Standard in industry; explain dual-licensing rationale transparently |

---

## Immediate Next Steps (Pre-Launch Checklist)

**Must be done before Hour 0:**
1. ~~**Legal:** AGPL-3.0 headers on all source files~~ DONE
2. ~~**GitHub:** LICENSE, CONTRIBUTING.md (with CLA), CODE_OF_CONDUCT.md~~ DONE
3. **GitHub:** README.md polish — hero section, install one-liner, screenshot/GIF, badges
4. **GitHub:** Social preview image, repo description, topics (ai-security, agent-monitoring, rust, linux)
5. **GitHub:** CLA Assistant bot configured and tested
6. **GitHub:** 10+ "good first issue" labels created and described
7. **GitHub:** Discussion board enabled with welcome post
8. **Content:** 60-second demo clip ready for X/Twitter
9. **Content:** Launch blog post drafted and ready to publish
10. **Discord:** Server created with channel structure

**Ready to launch when 1-10 are complete. Praxis commercial license can finalize in parallel during Week 2-3.**

---

*Document prepared for internal strategy discussion. JR Morton + Praxis AI. February 2026.*
