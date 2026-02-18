# ClawTower Config Layering Design

**Date:** 2026-02-16
**Status:** Approved
**Problem:** Config immutability (`chattr +i`) creates friction for user customizations, and upstream updates risk clobbering user settings.

## Principles

- Updates are invisible — users never worry about them
- User customizations always win
- No immutable flags — file permissions (root:root 644) are sufficient
- The agent (OpenClaw) cannot modify root-owned files, so the security model holds

## Config Layering

**Base:** `/etc/clawtower/config.toml` — upstream-owned, replaced on updates.

**Overrides:** `/etc/clawtower/config.d/*.toml` — user-owned, never touched by updates. Loaded alphabetically after base.

### Resolution Rules

- **Scalars:** last value wins (base → config.d files in alphabetical order)
- **Lists:** three modes:
  - `field = [...]` — full replacement
  - `field_add = [...]` — append to base list
  - `field_remove = [...]` — remove from base list
  - `_add` and `_remove` can combine in the same file
- **Nested tables:** merge field by field, same scalar/list rules apply

### Example

```toml
# /etc/clawtower/config.d/my-overrides.toml
[falco]
enabled = false

[netpolicy]
allowed_hosts_add = ["myapi.example.com"]
allowed_hosts_remove = ["wttr.in"]
```

## Policy Layering

**Base:** `/etc/clawtower/policies/default.yaml` — upstream-owned, replaced on updates.

**User policies:** `/etc/clawtower/policies/*.yaml` — loaded alphabetically, `default.yaml` always first.

### Resolution Rules

- Rules matched by `name` field
- User rule with same name **replaces the default rule entirely**
- New rules in user files are added to the rule set
- `enabled: false` disables a rule without deleting it

### Example

```yaml
# /etc/clawtower/policies/custom.yaml
rules:
  - name: "block-data-exfiltration"
    description: "Customized exfil rule"
    match:
      command: ["curl", "wget", "nc", "ncat", "netcat", "socat"]
      exclude_args:
        - "gottamolt.gg"
        - "wttr.in"
    action: critical

  - name: "detect-scheduled-tasks"
    enabled: false
```

### Tradeoff

Overriding a rule by name means the user owns that rule — upstream additions won't auto-merge. This is intentional: if you customize it, you maintain it.

## Update Flow

1. Replace `/etc/clawtower/config.toml` with new upstream version
2. Replace `/etc/clawtower/policies/default.yaml` with new upstream version
3. Never touch `config.d/*` or user policy files
4. Restart service

Users see: update happens, service restarts, customizations untouched.

## Install Flow

1. Write `config.toml` and `default.yaml`
2. Create empty `/etc/clawtower/config.d/` directory
3. Set ownership root:root 644 on all config files
4. No immutable flags at any point
5. Start service

## Implementation Scope

### Config loader (`src/config.rs`)
- After loading `config.toml`, scan `config.d/*.toml` alphabetically
- Apply merge logic: scalar replace, list `_add`/`_remove`
- Strip `_add`/`_remove` suffixes after merge so downstream code sees clean fields

### Policy loader (`src/policy.rs`)
- Load `default.yaml` first, then remaining `*.yaml` alphabetically
- Name-based rule merge: user rules replace or add, `enabled: false` disables
- Filter out disabled rules before passing to engine

### Install script
- Create `/etc/clawtower/config.d/`
- Remove all `chattr +i` / `chattr -i` calls
- Set ownership root:root 644

### Docs
- Update `TUNING.md` — point to `config.d/` instead of editing `config.toml`
- Update `DAY1-OPERATIONS.md` — remove chattr instructions
- New `CONFIGURATION.md` explaining layering

### Unchanged
- Runtime behavior, detection logic, alert pipeline
- BarnacleDefense vendor dir
- Audit chain, API, proxy
