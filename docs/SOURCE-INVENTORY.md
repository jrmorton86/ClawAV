# Source Inventory

> Auto-generated reference of all public items in the ClawAV codebase. Used for documentation cross-referencing.
>
> **Last updated:** 2026-02-14

## Modules & Module Docs

| File | Module Doc Summary |
|------|-------------------|
| `src/main.rs` | Entry point, CLI dispatch, spawns all monitoring subsystems |
| `src/admin.rs` | Admin socket and key management (Argon2 auth, Unix socket) |
| `src/aggregator.rs` | Alert deduplication and per-source rate limiting |
| `src/alerts.rs` | Core alert types (`Alert`, `Severity`, `AlertStore`) |
| `src/api.rs` | HTTP REST API server (status, alerts, health, security endpoints) |
| `src/audit_chain.rs` | Tamper-evident SHA-256 hash-chained audit log |
| `src/auditd.rs` | Linux audit log parser (SYSCALL, EXECVE, AVC records) |
| `src/behavior.rs` | Hardcoded behavioral threat detection (~200 patterns, 5 categories) |
| `src/cognitive.rs` | Cognitive file integrity monitoring for AI identity files |
| `src/config.rs` | TOML configuration loading and serialization |
| `src/falco.rs` | Falco eBPF/syscall alert integration |
| `src/firewall.rs` | UFW firewall state monitor (baseline + diff) |
| `src/journald.rs` | Journald-based log monitoring (network + SSH) |
| `src/logtamper.rs` | Audit log tampering detection (missing, replaced, truncated) |
| `src/netpolicy.rs` | Network policy enforcement (allowlist/blocklist) |
| `src/network.rs` | Network log parser for iptables/netfilter entries |
| `src/policy.rs` | User-configurable YAML policy engine |
| `src/proxy.rs` | API key vault proxy with DLP scanning |
| `src/samhain.rs` | Samhain FIM log parser |
| `src/scanner.rs` | Periodic security posture scanner (30+ checks) |
| `src/secureclaw.rs` | SecureClaw vendor threat pattern engine (4 JSON databases) |
| `src/sentinel.rs` | Real-time file integrity via inotify (quarantine/restore) |
| `src/slack.rs` | Slack webhook notification sender (primary + backup) |
| `src/tui.rs` | Terminal UI dashboard (ratatui, 6 tabs) |
| `src/update.rs` | Self-update from GitHub releases (SHA-256 + Ed25519) |
| `src/bin/clawsudo.rs` | Sudo proxy/gatekeeper binary |

## Public Structs

| Struct | Module | Fields (key) |
|--------|--------|-------------|
| `AdminRequest` | admin | `key`, `command`, `args` |
| `AdminResponse` | admin | `success`, `message`, `data` |
| `AdminSocket` | admin | socket path, key hash, rate limiter |
| `AggregatorConfig` | aggregator | `dedup_window`, `scan_dedup_window`, `rate_limit_per_source`, `rate_limit_window` |
| `Aggregator` | aggregator | config, dedup map, rate limits, chain, store |
| `Alert` | alerts | `timestamp`, `severity`, `source`, `message` |
| `AlertStore` | alerts | alerts vec, max_size |
| `AlertRingBuffer` | api | alerts deque, max capacity |
| `AuditEntry` | audit_chain | `seq`, `ts`, `severity`, `source`, `message`, `prev_hash`, `hash` |
| `AuditChain` | audit_chain | file path, last_seq, last_hash |
| `ParsedEvent` | auditd | `syscall_name`, `command`, `args`, `file_path`, `success`, `raw`, `actor`, `ppid_exe` |
| `CognitiveBaseline` | cognitive | hashes map, workspace_dir |
| `CognitiveAlert` | cognitive | `file`, `kind`, `watched` |
| `Config` | config | all subsystem config sections |
| `GeneralConfig` | config | `watched_user`, `watched_users`, `watch_all_users`, `min_alert_level`, `log_file` |
| `SlackConfig` | config | `enabled`, `webhook_url`, `backup_webhook_url`, `channel`, `min_slack_level`, `heartbeat_interval` |
| `AuditdConfig` | config | `log_path`, `enabled` |
| `NetworkConfig` | config | `log_path`, `log_prefix`, `enabled`, `source`, `allowlisted_cidrs`, `allowlisted_ports` |
| `FalcoConfig` | config | `enabled`, `log_path` |
| `SamhainConfig` | config | `enabled`, `log_path` |
| `SshConfig` | config | `enabled` |
| `ApiConfig` | config | `enabled`, `bind`, `port` |
| `ScansConfig` | config | `interval` |
| `ProxyConfig` | config | `enabled`, `bind`, `port`, `key_mapping`, `dlp` |
| `KeyMapping` | config | `virtual_key`, `real`, `provider`, `upstream` |
| `DlpConfig` | config | `patterns` |
| `DlpPattern` | config | `name`, `regex`, `action` |
| `PolicyConfig` | config | `enabled`, `dir` |
| `NetPolicyConfig` | config | `enabled`, `allowed_hosts`, `allowed_ports`, `blocked_hosts`, `mode` |
| `SentinelConfig` | config | `enabled`, `watch_paths`, `quarantine_dir`, `shadow_dir`, `debounce_ms`, `scan_content`, `max_file_size_kb` |
| `WatchPathConfig` | config | `path`, `patterns`, `policy` |
| `AutoUpdateConfig` | config | `enabled`, `interval` |
| `NetworkAllowlist` | network | `cidrs`, `ports` |
| `NetPolicy` | netpolicy | config fields |
| `PolicyRule` | policy | `name`, `description`, `match_spec`, `action`, `enforcement` |
| `MatchSpec` | policy | `command`, `command_contains`, `file_access`, `exclude_args` |
| `PolicyVerdict` | policy | `rule_name`, `severity`, `message` |
| `PolicyEngine` | policy | rules vec |
| `ProxyServer` | proxy | config, alert_tx |
| `SecureClawConfig` | secureclaw | `enabled`, `vendor_dir` |
| `SecureClawEngine` | secureclaw | compiled patterns (4 categories) |
| `CompiledPattern` | secureclaw | `name`, `category`, `regex`, `severity`, `action` |
| `PatternMatch` | secureclaw | `pattern_name`, `category`, `matched_text`, `severity`, `action` |
| `ScanResult` | scanner | `category`, `status`, `details`, `timestamp` |
| `SecurityScanner` | scanner | unit struct |
| `Sentinel` | sentinel | watcher, config, shadow/quarantine state |
| `SlackNotifier` | slack | webhook URLs, channel |
| `App` | tui | tabs, alerts, scan results, config editor state |
| `ConfigField` | tui | field name, value, section, field_type |
| `SudoPopup` | tui | input, status |

## Public Enums

| Enum | Module | Variants |
|------|--------|---------|
| `Severity` | alerts | `Info`, `Warning`, `Critical` |
| `Actor` | auditd | `Agent`, `Human`, `Unknown` |
| `BehaviorCategory` | behavior | `DataExfiltration`, `PrivilegeEscalation`, `SecurityTamper`, `Reconnaissance`, `SideChannel`, `SecureClawMatch` |
| `CognitiveAlertKind` | cognitive | `Modified { diff }`, `Deleted`, `NewFile` |
| `WatchPolicy` | config | `Protected`, `Watched` |
| `ScanStatus` | scanner | `Pass`, `Warn`, `Fail` |
| `DlpResult` | proxy | `Clean`, `Blocked(String)`, `Redacted(String)` |
| `TuiEvent` | tui | `Key(KeyEvent)`, `Tick`, `Alert(Alert)`, `ScanResults(Vec<ScanResult>)` |
| `ConfigFocus` | tui | `Sections`, `Fields` |
| `FieldType` | tui | `Text`, `Bool`, `Number`, `Select(Vec<String>)` |
| `SudoStatus` | tui | `Idle`, `Waiting`, `Success`, `Failed(String)` |

## Public Functions (standalone)

| Function | Module | Signature Summary |
|----------|--------|------------------|
| `generate_admin_key` | admin | `() -> Result<(String, String)>` |
| `hash_key` | admin | `(key: &str) -> Result<String>` |
| `verify_key` | admin | `(key: &str, hash: &str) -> bool` |
| `init_admin_key` | admin | `(hash_path: &Path) -> Result<()>` |
| `run_verify_audit` | audit_chain | `(path: Option<&str>) -> Result<()>` |
| `extract_field` | auditd | `(line: &str, field: &str) -> Option<&str>` |
| `parse_to_event` | auditd | `(line: &str, watched_users: Option<&[String]>) -> Option<ParsedEvent>` |
| `check_tamper_event` | auditd | `(event: &ParsedEvent) -> Option<Alert>` |
| `event_to_alert` | auditd | `(event: &ParsedEvent) -> Alert` |
| `parse_audit_line` | auditd | `(line: &str, watched_users: Option<&[String]>) -> Option<Alert>` |
| `classify_behavior` | behavior | `(event: &ParsedEvent) -> Option<(BehaviorCategory, Severity)>` |
| `scan_cognitive_integrity` | cognitive | `(workspace_dir, baseline_path, secureclaw) -> Vec<ScanResult>` |
| `default_allowlisted_cidrs` | config | `() -> Vec<String>` |
| `default_allowlisted_ports` | config | `() -> Vec<u16>` |
| `parse_falco_line` | falco | `(line: &str) -> Option<Alert>` |
| `journald_available` | journald | `() -> bool` |
| `scan_audit_log_health` | logtamper | `(log_path: &Path) -> ScanResult` |
| `parse_iptables_line` | network | `(line: &str, prefix: &str) -> Option<Alert>` |
| `parse_samhain_line` | samhain | `(line: &str) -> Option<Alert>` |
| `new_shared_store` | api | `(max: usize) -> SharedAlertStore` |
| `new_shared_scan_results` | scanner | `() -> SharedScanResults` |
| `scan_firewall` | scanner | `() -> ScanResult` |
| `parse_ufw_status` | scanner | `(output: &str) -> ScanResult` |
| `scan_auditd` | scanner | `() -> ScanResult` |
| `parse_auditctl_status` | scanner | `(output: &str) -> ScanResult` |
| `scan_integrity` | scanner | `() -> ScanResult` |
| `scan_immutable_flags` | scanner | `() -> ScanResult` |
| `check_lsattr_immutable` | scanner | `(output: &str) -> bool` |
| `scan_apparmor_protection` | scanner | `() -> ScanResult` |
| `scan_secureclaw_sync` | scanner | `() -> ScanResult` |
| `scan_updates` | scanner | `() -> ScanResult` |
| `scan_ssh` | scanner | `() -> ScanResult` |
| `scan_listening_services` | scanner | `() -> ScanResult` |
| `scan_resources` | scanner | `() -> ScanResult` |
| `parse_disk_usage` | scanner | `(output: &str) -> ScanResult` |
| `scan_sidechannel_mitigations` | scanner | `() -> ScanResult` |
| `scan_crontab_audit` | scanner | `() -> ScanResult` |
| `scan_world_writable_files` | scanner | `() -> ScanResult` |
| `scan_suid_sgid_binaries` | scanner | `() -> ScanResult` |
| `scan_kernel_modules` | scanner | `() -> ScanResult` |
| `scan_docker_security` | scanner | `() -> ScanResult` |
| `scan_password_policy` | scanner | `() -> ScanResult` |
| `scan_open_file_descriptors` | scanner | `() -> ScanResult` |
| `scan_dns_resolver` | scanner | `() -> ScanResult` |
| `scan_ntp_sync` | scanner | `() -> ScanResult` |
| `scan_failed_login_attempts` | scanner | `() -> ScanResult` |
| `scan_zombie_processes` | scanner | `() -> ScanResult` |
| `scan_swap_tmpfs_security` | scanner | `() -> ScanResult` |
| `scan_environment_variables` | scanner | `() -> ScanResult` |
| `scan_package_integrity` | scanner | `() -> ScanResult` |
| `scan_core_dump_settings` | scanner | `() -> ScanResult` |
| `scan_network_interfaces` | scanner | `() -> ScanResult` |
| `scan_systemd_hardening` | scanner | `() -> ScanResult` |
| `scan_user_account_audit` | scanner | `() -> ScanResult` |
| `shadow_path_for` | sentinel | `(shadow_dir, file_path) -> PathBuf` |
| `quarantine_path_for` | sentinel | `(quarantine_dir, file_path) -> PathBuf` |
| `generate_unified_diff` | sentinel | `(old, new, filename) -> String` |
| `is_log_rotation` | sentinel | `(file_path: &str) -> bool` |
| `lookup_virtual_key` | proxy | `(mapping, key) -> Option<(&str, &str, &str)>` |
| `scan_dlp` | proxy | `(patterns, body) -> DlpResult` |
| `run_update` | update | `(args: &[String]) -> Result<()>` |
| `is_newer_version` | update | `(current, remote) -> bool` |

## Public Type Aliases

| Alias | Module | Definition |
|-------|--------|-----------|
| `SharedAlertStore` | api | `Arc<Mutex<AlertRingBuffer>>` |
| `SharedScanResults` | scanner | `Arc<Mutex<Vec<ScanResult>>>` |

## See Also

- [CLAUDE.md](../CLAUDE.md) — Full module guide with descriptions and usage patterns
- [ARCHITECTURE.md](ARCHITECTURE.md) — Module dependency graph and data flow
- [CONFIGURATION.md](CONFIGURATION.md) — Config struct field reference
