# Your AI Agent Has Root Access. Now What?

*How I built an OS-level watchdog for AI agents — and why I open-sourced it.*

---

AI agents have gone from “cool demo” to “part of production.”

They write code, run shell commands, touch the filesystem, call APIs, and sometimes use `sudo`. That’s powerful. It’s also a little terrifying.

If you’re running agents on real infrastructure, here’s the question I keep coming back to:

**Who is watching what the agent is doing at the OS level?**

I’m J.R. Morton. I work in security and infrastructure hardening. Over the last year I kept seeing the same gap: we have prompt guardrails, static scanners, and container boundaries — but once an agent is actively executing commands, visibility gets thin fast.

So I built ClawTower.

---

## Why this is a different security problem

Three things make agent security weird:

1. **The “user” can be the threat.**
	Agents are authorized users with real permissions. If they get manipulated (prompt injection, poisoned context, model mistakes), they can still do damage with valid access.

2. **The agent may be able to turn off its own guardrails.**
	If your monitor is just another process/config/service, an agent with enough permissions can stop it.

3. **Containers are useful, but not enough.**
	Isolation helps. But it doesn’t automatically give you great telemetry, tamper evidence, or a clean forensic trail.

---

## What ClawTower is

ClawTower is an OS-level security watchdog for Linux hosts running AI agents.

It monitors syscall and system activity (auditd, inotify, network policy checks), and it’s designed so the monitored agent can’t quietly disable or rewrite it.

The core design pattern is the **“swallowed key”** idea:

- admin key shown once, then only stored as an Argon2 hash
- protected files marked immutable with `chattr +i`
- service-level hardening and alerting on tamper attempts

In plain English: the thing being watched shouldn’t be able to fire the security guard.

---

## What it monitors (without the marketing fog)

- **Behavioral detection** for exfiltration, priv-esc, persistence, recon, and more
- **File integrity** with protected/watched policies, shadow copies, and restore workflows
- **Cognitive file protection** for identity files like `SOUL.md` and `AGENTS.md`
- **Network policy enforcement** (allowlist/blocklist modes)
- **30+ periodic security scans** (SSH hardening, SUID checks, firewall posture, etc.)
- **Hash-chained audit log** so retroactive edits are detectable
- **`clawsudo` gatekeeper** for policy-driven privileged command control

Alerts flow into both a terminal dashboard and Slack.

---

## Agent-agnostic by design

ClawTower doesn’t require SDK hooks into one specific framework.

If an agent runs on Linux under a user account, ClawTower can monitor that UID. That includes coding agents, autonomous workflows, and custom agent stacks.

---

## Why AGPL

I’m shipping this under **AGPL-3.0**.

Short version: if someone turns it into a hosted product, they need to publish their changes. I want improvements to flow back into the project, especially for a security tool where auditability matters.

If software is guarding your infrastructure with elevated privileges, you should be able to inspect the code.

---

## What surprised me while building it

- **Detection logic is the hard part.** Collecting events is easy compared to deciding what behavior is truly suspicious.
- **Tamper resistance takes layering.** One protection isn’t enough; you need defense in depth.
- **Noise management is everything.** Without dedup/rate limiting, alerts become useless fast.

---

## Try it

ClawTower is written in Rust and runs on Linux (`x86_64`, `aarch64`).

One-line install:

```bash
curl -sSL https://raw.githubusercontent.com/ClawTower/ClawTower/main/scripts/oneshot-install.sh | sudo bash
```

Or from source:

```bash
git clone https://github.com/ClawTower/ClawTower.git
cd ClawTower
cargo build --release
```

**GitHub:** [github.com/ClawTower/ClawTower](https://github.com/ClawTower/ClawTower)

If you run agents in real environments, I’d love your feedback — especially the rough edges.

---

## What I’ll write about here

- Practical agent attack paths (not just theory)
- Detection design tradeoffs and false-positive tuning
- Lessons from adversarial testing
- Hardening patterns that actually hold up under pressure

If you’re building or defending agent infrastructure, welcome — that’s exactly who this is for.

— J.R. Morton
