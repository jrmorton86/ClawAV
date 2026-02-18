# Glob Matching Bug — Why `*.json` Patterns Were Broken

## The Bug

Sentinel directory watches used glob-style patterns like `*.json`, `*.service`,
`*.timer`, `*.desktop`, `*.md`. None of them actually matched any files.

## Root Cause

`policy_for_path()` in `sentinel.rs` line 120:
```rust
if pattern == "*" || filename == *pattern {
    return Some(wp.policy.clone());
}
```

This is an **exact string comparison**, not glob matching. `filename == "*.json"`
only matches a file literally named `*.json` — not `device.json`, not
`creds.json`, not anything useful.

The `glob_match` crate was already a dependency (used for content scan exclusions)
but was never used in the sentinel path matching code.

## Affected Watches

Every directory watch with non-`*` patterns was broken:

| Directory | Pattern | Intended | Actual |
|-----------|---------|----------|--------|
| `.openclaw/credentials` | `*.json` | All JSON credential files | Nothing |
| `.config/systemd/user` | `*.service`, `*.timer` | Systemd persistence | Nothing |
| `.config/autostart` | `*.desktop` | Autostart persistence | Nothing |
| `workspace/memory` | `*.md` | Memory file poisoning | Nothing |
| `Downloads` | `*.md`, `*.txt`, `*.json`, `*.html` | Indirect injection | Nothing |
| `dist-packages` | `sitecustomize.py`, `usercustomize.py` | Python persistence | Worked (exact match) |
| `.mcp` | `*.json`, `*.yaml` | MCP config integrity | Nothing |

Only patterns that were literal filenames (`sitecustomize.py`, `SKILL.md`,
`creds.json`, `.package-lock.json`) worked correctly since exact match
happened to be the right behavior.

## Why It Wasn't Caught

1. The `*` (match-all) pattern worked correctly — most watches used this
2. Directory watches with glob patterns are less common in the config
3. No test exercised glob matching (tests used `*` or exact filenames)
4. The sentinel logged "watching 33 paths" regardless of pattern correctness

## Fix

```rust
// Before (exact match only)
if pattern == "*" || filename == *pattern {

// After (proper glob matching)
if pattern == "*" || glob_match::glob_match(pattern, &filename) {
```

Added tests:
- `test_policy_for_path_glob_json_match` — device.json, openclaw.json, settings.json
- `test_policy_for_path_glob_rejects_non_json` — README.txt should not match
- `test_policy_for_path_credentials_glob_match` — creds.json in credentials dir

## Lesson

**If a feature isn't tested, assume it's broken.** The glob pattern support
looked correct in the config but was never exercised in tests. A single test
case with a `*.json` pattern would have caught this immediately.
