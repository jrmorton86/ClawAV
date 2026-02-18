# ClawTower Website Design Notes

## Core Message

**"Runtime security for AI agents. Any agent. Any framework."**

ClawTower is not an OpenClaw plugin — it's an OS-level security layer for any AI agent running on Linux. Position it as infrastructure, not an accessory.

---

## Site Structure

### 1. Hero Section

**Headline:** "Who watches the AI?"
**Subhead:** "ClawTower is tamper-proof runtime security for autonomous AI agents — Claude Code, Codex, Devin, OpenClaw, or your own. OS-level monitoring that the agent can't disable."
**CTA:** `curl -sSL ... | sudo bash` one-liner + GitHub link

Visual: Terminal animation showing ClawTower catching an exfiltration attempt in real-time (TUI screenshot or animated SVG).

### 2. The Problem

Brief, punchy section:

- AI agents have real system access — shell, filesystem, network
- They can be compromised via prompt injection, poisoned context, malicious plugins
- Traditional antivirus scans files — it doesn't understand agent *behavior*
- Static marketplace scanning catches known threats, not runtime exploits
- **The agent itself might try to disable its own monitoring**

### 3. How It Works (3 pillars)

**Monitor** — Syscall-level behavioral analysis via auditd. File integrity monitoring via inotify. Network connection tracking. Knows the difference between a human and an agent acting on the system.

**Enforce** — Policy engine + clawsudo gatekeeper. The agent runs privileged commands through ClawTower's policy layer, not raw sudo. Allowlist, blocklist, or alert on any command pattern.

**Protect** — The "swallowed key" pattern. Once installed, ClawTower is immutable. The binary is locked (`chattr +i`), the service is protected by systemd, the admin key is hashed. The agent cannot modify, disable, or uninstall it. Every tamper attempt is logged and alerted.

### 4. How ClawTower Fits (Security Stack)

Visual: layered diagram showing the full agent security stack

```
┌─────────────────────────────────────────┐
│  Marketplace Scanning (pre-install)     │  ← VirusTotal, npm audit, etc.
│  Static code analysis, signature scan   │
├─────────────────────────────────────────┤
│  Code Review (pre-execution)            │  ← LLM code insight, manual review
│  Behavioral analysis of source code     │
├─────────────────────────────────────────┤
│  ██ CLAWTOWER — Runtime Monitoring ██      │  ← THIS IS US
│  Syscall monitoring, policy enforcement │
│  File integrity, behavioral analysis    │
│  Tamper-proof, agent-agnostic           │
├─────────────────────────────────────────┤
│  Network Policy (continuous)            │  ← ClawTower netpolicy + firewall
│  Outbound allowlisting, DLP scanning    │
└─────────────────────────────────────────┘
```

Key callout: **"Static scanning catches known threats. ClawTower catches what happens next."**

Mention OpenClaw's VirusTotal integration specifically as an example of pre-install scanning that ClawTower complements. Also mention npm audit, Snyk, etc. — we're not just an OpenClaw companion, we fit into any security stack.

### 5. Works With Everything

Grid of logos/icons:
- OpenClaw
- Claude Code (Anthropic)
- Codex CLI (OpenAI)
- Aider
- Devin
- SWE-agent
- LangChain / CrewAI / AutoGen
- "Your custom agent"

Subtext: "No SDK. No integration code. ClawTower works at the OS level — install it, point it at your agent's user, done."

### 6. What It Catches

Real examples, not abstract features:

| Threat | How ClawTower Catches It |
|--------|----------------------|
| Prompt injection causes data exfiltration | Behavioral analysis flags unusual `curl`/`scp` to unknown hosts |
| Malicious skill modifies agent identity files | Cognitive file protection detects SOUL.md/AGENTS.md tampering |
| Agent tries to disable its own monitoring | Immutable binary + systemd protection + tamper alert |
| Reverse shell spawned via code execution | Auditd behavioral engine classifies as privilege escalation |
| API keys leaked in outbound requests | DLP proxy scans and redacts credentials |
| Cron persistence planted by compromised agent | Crontab auditing scanner detects unauthorized entries |

### 7. Daily Security Scan

Highlight the comprehensive daily scan capability:
- 30+ security scanners run on schedule
- Firewall, SSH, Docker, kernel params, open ports, SUID binaries, world-writable files
- Skill/plugin integrity verification (hash comparison)
- BarnacleDefense pattern database refresh
- Results logged to hash-chained audit trail
- Alerts via Slack on any findings

### 8. Open Source

- MIT licensed
- Rust (fast, safe, single binary)
- 170+ tests
- CI/CD via GitHub Actions
- Cross-compiled for x86_64 and aarch64
- One-line install

CTA: GitHub stars, contribute, report issues

---

## Design Direction

- **Dark theme primary** — security product, terminal aesthetic
- Clean, technical, not corporate. Think Tailscale or Warp vibes, not McAfee.
- Terminal screenshots and code snippets as visuals (real, not mockups)
- Minimal animation — maybe the hero terminal demo, nothing else flashy
- Mobile responsive but desktop-first (target audience is developers/ops)

## Domain

TBD — candidates:
- clawtower.dev
- clawtower.io
- clawtower.security
- getclawtower.com

## Tech Stack (suggestion)

- Static site (Astro or plain HTML/CSS) — no reason for a framework
- Hosted on GitHub Pages or Cloudflare Pages (free, fast)
- No analytics initially, maybe Plausible later

---

## Content Priorities

1. **Clarity on what layer we occupy** — runtime, not static scanning
2. **Agent-agnostic messaging** — not an OpenClaw plugin
3. **The "swallowed key" differentiator** — no other tool does this
4. **Complement, don't compete** — show the full stack, where we fit
5. **Easy install** — one command, zero config to start
