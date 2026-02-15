# ClawAV Documentation Index

Quick map to every doc in this project. Start with what you need.

## Getting Started

| Document | What's in it |
|----------|-------------|
| [README](../README.md) | Project overview, features, quick start, config basics |
| [INSTALL.md](INSTALL.md) | Full installation walkthrough, hardening steps, systemd setup, uninstall |
| [CONFIGURATION.md](CONFIGURATION.md) | Every config field — types, defaults, TOML examples |

## Architecture & Internals

| Document | What's in it |
|----------|-------------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Module dependency graph, data flow diagrams, threat model |
| [ALERT-PIPELINE.md](ALERT-PIPELINE.md) | Alert model, aggregator dedup/rate-limiting, Slack/TUI delivery |
| [MONITORING-SOURCES.md](MONITORING-SOURCES.md) | All 9 real-time data sources (auditd, journald, falco, etc.) |
| [SECURITY-SCANNERS.md](SECURITY-SCANNERS.md) | All 30+ periodic security scanners — pass/warn/fail conditions |

## Features Deep Dives

| Document | What's in it |
|----------|-------------|
| [SENTINEL.md](SENTINEL.md) | Real-time file integrity: inotify, shadow copies, quarantine, content scanning |
| [POLICIES.md](POLICIES.md) | YAML policy writing for detection rules and clawsudo enforcement |
| [CLAWSUDO-AND-POLICY.md](CLAWSUDO-AND-POLICY.md) | clawsudo gatekeeper, admin key, audit chain, API proxy, LD_PRELOAD guard |
| [API.md](API.md) | HTTP REST API endpoints and response formats |

## For AI Agents / Contributors

| Document | What's in it |
|----------|-------------|
| [CLAUDE.md](../CLAUDE.md) | LLM onboarding — module guide, key patterns, common tasks, glossary |
| [SOURCE-INVENTORY.md](SOURCE-INVENTORY.md) | Complete inventory of all public items (structs, enums, functions) |
| [AUDIT-LOG.md](AUDIT-LOG.md) | Internal documentation audit log (maintainer reference, not user-facing) |

## Suggested Reading Order

**New user?** README → INSTALL.md → CONFIGURATION.md

**Understanding the system?** ARCHITECTURE.md → ALERT-PIPELINE.md → MONITORING-SOURCES.md

**Setting up file protection?** SENTINEL.md → POLICIES.md

**Working on the code?** CLAUDE.md → ARCHITECTURE.md → the relevant feature doc
