# Audit Log — Round 6 (Hostile Review)

Methodology: extracted every `pub` item from all `src/*.rs` files, cross-referenced against all docs, verified config defaults against `Default` impls, checked file paths, checked Cargo.toml deps.

---

## File: CLAUDE.md

- [FIXED] `CognitiveAlert` struct fields listed as `path`, `kind`, `message`, `diff` — actual fields are `file` (PathBuf), `kind` (CognitiveAlertKind), `watched` (bool). Corrected.
- [FIXED] `CognitiveAlertKind` variants listed as `Modified`, `Deleted`, `NewUnexpected`, `ContentThreat`, `BaselineMissing` — actual variants are `Modified { diff: Option<String> }`, `Deleted`, `NewFile`. Corrected.
- [FIXED] `BehaviorCategory` listed 5 variants but code has 6 — missing `BarnacleDefenseMatch` (marked `#[allow(dead_code)]`). Added.
- [FIXED] Section "config.rs (Sub-structs)" implied all config structs live in `config.rs`, but `BarnacleDefenseConfig` is defined in `barnacle.rs` and imported. Clarified header and description.
- [VERIFIED] All channel capacities: `raw_tx` = 1000, `alert_tx` = 1000, `slack_tx` = 100 — match code.
- [VERIFIED] `AlertStore` capacity = 500 (in `tui.rs App::new()`) — matches ALERT-PIPELINE.md.
- [VERIFIED] `AggregatorConfig` defaults: dedup 30s, scan dedup 1h, rate limit 20/60s, critical 5s — all correct.
- [VERIFIED] All `Config` section defaults match `Default` impls (checked each struct).
- [VERIFIED] CLI subcommands listed match `main.rs` dispatch.
- [VERIFIED] All 26 source files listed in module table exist.
- [VERIFIED] `src/release-key.pub` exists (32 bytes).
- [VERIFIED] `policies/default.yaml` and `policies/clawsudo.yaml` exist.
- [VERIFIED] `.github/workflows/ci.yml` and `release.yml` exist.
- [VERIFIED] `config.example.yaml` and `config.toml` both exist.
- [VERIFIED] Cognitive protected files list matches code: SOUL.md, IDENTITY.md, TOOLS.md, AGENTS.md, USER.md, HEARTBEAT.md.
- [VERIFIED] Cognitive watched files: MEMORY.md — correct.
- [VERIFIED] Sentinel default watch_paths: SOUL.md (protected), AGENTS.md (protected), MEMORY.md (watched) — matches `SentinelConfig::default()`.
- [VERIFIED] All `default_*` functions in config.rs match documented defaults.
- [VERIFIED] `NetPolicyConfig::default()` allowed_ports = [80, 443, 53] — matches docs.
- [VERIFIED] `default_allowlisted_cidrs()` = 6 CIDRs including 224.0.0.0/4 — matches docs.
- [VERIFIED] `default_allowlisted_ports()` = [443, 53, 123, 5353] — matches docs.

## File: README.md

- [VERIFIED] All scripts listed in "Available Scripts" table exist in `scripts/`.
- [VERIFIED] Feature descriptions match actual module capabilities.
- [VERIFIED] Config example values match code defaults.
- [VERIFIED] Architecture diagram accurately reflects data flow.

## File: docs/ARCHITECTURE.md

- [FIXED] Module tree listed `preload/interpose.c` — actual path is `src/preload/interpose.c`. Corrected.
- [VERIFIED] Module dependency graph matches actual `mod` declarations and `use` imports.
- [VERIFIED] Data flow diagram matches channel wiring in `main.rs`.
- [VERIFIED] Aggregator dedup/rate-limit parameters match code defaults.
- [VERIFIED] Hash chain format (seq|ts|severity|source|message|prev_hash) matches `AuditChain::append()`.
- [VERIFIED] Firewall polling interval 30s matches `firewall.rs`.
- [VERIFIED] Behavior classification priority order matches code evaluation order.

## File: docs/CONFIGURATION.md

- [VERIFIED] All 15 config sections documented with correct struct names.
- [VERIFIED] "Five sections required" claim — checked: `general`, `slack`, `auditd`, `network`, `scans` lack `#[serde(default)]` on the `Config` struct fields. Correct.
- [VERIFIED] Every field type, default value, and serde attribute matches source code.
- [VERIFIED] `BarnacleDefenseConfig` struct name and fields correct (defined in `barnacle.rs`).
- [VERIFIED] `WatchPolicy` enum variants: `Protected`, `Watched` — correct.
- [VERIFIED] `KeyMapping` has `#[serde(alias = "virtual")]` on `virtual_key` — documented.

## File: docs/ALERT-PIPELINE.md

- [VERIFIED] Alert struct fields match `alerts.rs`: `timestamp`, `severity`, `source`, `message`.
- [VERIFIED] Severity emoji and Slack colors match code.
- [VERIFIED] AlertStore capacity 500 — matches `tui.rs`.
- [VERIFIED] Channel capacities (1000, 1000, 100) match `main.rs`.
- [VERIFIED] TUI tab list (6 tabs) with correct content descriptions.
- [VERIFIED] Config editor section list matches `tui.rs` (12 sections, sentinel/ssh/auto_update excluded).

## File: docs/SENTINEL.md

- [VERIFIED] Shadow path naming scheme (SHA-256 prefix + filename) matches `shadow_path_for()`.
- [VERIFIED] Quarantine naming (timestamp_filename) matches `quarantine_path_for()`.
- [VERIFIED] Log rotation detection checks `.1`, `.0`, `.gz` siblings — matches `is_log_rotation()`.
- [VERIFIED] Default watch paths table (3 paths) matches `SentinelConfig::default()`.
- [VERIFIED] Debounce default 200ms — correct.
- [VERIFIED] Cognitive comparison table is accurate.

## File: docs/SECURITY-SCANNERS.md

- [VERIFIED] All scanner functions listed exist in `src/scanner.rs`.
- [VERIFIED] Category names match code (e.g., `scan_zombie_processes()` → category `"process_health"`).
- [VERIFIED] ScanResult struct fields match code.
- [VERIFIED] ScanStatus → Severity mapping (Warn→Warning, Fail→Critical) matches `to_alert()`.
- [VERIFIED] BarnacleDefense JSON file formats match `BarnacleDefenseEngine::load()` parsing.

## File: docs/MONITORING-SOURCES.md

- [FIXED] Network monitoring prefix example was `"[CLAWTOWER-NET]"` (with brackets) — actual config default is `"CLAWTOWER_NET"` (no brackets). Corrected to match.
- [VERIFIED] Auditd record types (SYSCALL, EXECVE, AVC) and parsing details match code.
- [VERIFIED] Actor enum: Agent (auid=4294967295), Human, Unknown — matches code.
- [VERIFIED] Falco priority mapping matches `parse_falco_line()`.
- [VERIFIED] Samhain severity mapping matches `parse_samhain_line()`.
- [VERIFIED] SSH event classification (Accepted→Info, Failed→Warning) matches code.
- [VERIFIED] Log tamper detection signals (missing, replaced, truncated) match code.
- [VERIFIED] NetPolicy two modes and wildcard matching match code.

## File: docs/POLICIES.md

- [FIXED] YAML schema `exclude_args` and `file_access` fields were not marked as detection-engine-only. clawsudo's independent policy loader (`src/bin/clawsudo.rs`) only supports `command` and `command_contains`. Added clarifying notes.
- [VERIFIED] Policy evaluation order: detection = highest severity wins, clawsudo = first match wins — matches code.
- [VERIFIED] Fail-secure behavior (no rules = deny all) in clawsudo — confirmed in code.
- [VERIFIED] Policy file locations match code (both `./policies/` and `/etc/clawtower/policies/`).

## File: docs/CLAWSUDO-AND-POLICY.md

- [VERIFIED] Exit codes (0, 1, 77, 78) match clawsudo.rs code.
- [VERIFIED] Admin key format `OCAV-` + 64 hex chars matches `generate_admin_key()`.
- [VERIFIED] Admin socket commands (status, scan, pause, config-update) match code.
- [VERIFIED] Rate limiting (3 failures → 1h lockout) matches code.
- [VERIFIED] Audit chain hash computation formula matches code.
- [VERIFIED] LD_PRELOAD guard interposed syscalls match `interpose.c`.
- [VERIFIED] Match criteria table correctly marks `exclude_args` and `file_access` as detection-only.

## File: docs/API.md

- [VERIFIED] All 4 endpoints match `src/api.rs` route handling.
- [VERIFIED] Ring buffer size 1000, returns last 100 — matches code.
- [VERIFIED] Severity display values (INFO, WARN, CRIT) match `Severity` Display impl.
- [VERIFIED] Default bind `0.0.0.0:18791` matches `ApiConfig::default()`.

## File: docs/INSTALL.md

- [VERIFIED] All scripts referenced exist in `scripts/`.
- [VERIFIED] CLI commands table matches `main.rs` dispatch.
- [VERIFIED] Admin key storage path `/etc/clawtower/admin.key.hash` matches code.

## Cargo.toml Dependencies

All 24 dependencies verified as used in source code:
- [VERIFIED] `libc`, `ratatui`, `crossterm`, `tokio`, `serde`, `serde_json`, `reqwest`, `chrono`, `toml`, `notify`, `anyhow`, `hyper`, `sha2`, `tracing`, `tracing-subscriber`, `argon2`, `rand`, `hex`, `regex`, `serde_yaml`, `glob-match`, `ipnet`, `ed25519-dalek` — all imported and used.
- [VERIFIED] Dev dependency `tempfile` used in tests.
- [VERIFIED] Release profile: `strip = true`, `lto = true`, `opt-level = "z"` — matches CLAUDE.md.
