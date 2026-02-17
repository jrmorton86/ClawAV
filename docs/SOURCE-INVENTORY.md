# Source Inventory

> Auto-generated reference of all public items in the ClawTower codebase.
>
> **Last updated:** 2026-02-16

## src/admin.rs

- `pub struct AdminRequest` — Incoming admin command (`key`, `command`, `args`)
- `pub struct AdminResponse` — Response payload (`success`, `message`, `data`)
- `pub struct AdminSocket` — Unix socket listener with Argon2 key auth and rate limiting
- `pub fn generate_admin_key() -> Result<(String, String)>` — Generate new admin key pair
- `pub fn hash_key(key: &str) -> Result<String>` — Argon2 hash an admin key
- `pub fn verify_key(key: &str, hash: &str) -> bool` — Verify key against stored hash
- `pub fn init_admin_key(hash_path: &Path) -> Result<()>` — Initialize admin key file

## src/aggregator.rs

- `pub struct AggregatorConfig` — Dedup window, rate limit settings
- `pub struct Aggregator` — Alert deduplication and per-source rate limiting engine
- `pub async fn run_aggregator(...)` — Main aggregator loop processing incoming alerts

## src/alerts.rs

- `pub enum Severity` — `Info`, `Warning`, `Critical`
- `pub struct Alert` — Core alert type (`timestamp`, `severity`, `source`, `message`)
- `pub struct AlertStore` — In-memory alert storage with max size

## src/api.rs

- `pub struct AlertRingBuffer` — Fixed-capacity ring buffer for recent alerts
- `pub type SharedAlertStore` — `Arc<Mutex<AlertRingBuffer>>`
- `pub fn new_shared_store(max: usize) -> SharedAlertStore` — Create shared alert store
- `pub async fn run_api_server(bind, port, store) -> Result<()>` — Start HTTP REST API server

## src/audit_chain.rs

- `pub struct AuditEntry` — Single hash-chained audit record (`seq`, `ts`, `severity`, `source`, `message`, `prev_hash`, `hash`)
- `pub struct AuditChain` — Tamper-evident SHA-256 hash-chained audit log
- `pub fn run_verify_audit(path: Option<&str>) -> Result<()>` — Verify audit chain integrity

## src/auditd.rs

- `pub const RECOMMENDED_AUDIT_RULES: &[&str]` — Recommended auditd rule set
- `pub enum Actor` — `Agent`, `Human`, `Unknown`
- `pub struct ParsedEvent` — Parsed audit event (`syscall_name`, `command`, `args`, `file_path`, `success`, `raw`, `actor`, `ppid_exe`)
- `pub fn extract_field<'a>(line: &'a str, field: &str) -> Option<&'a str>` — Extract key=value field from audit line
- `pub fn parse_to_event(line, watched_users) -> Option<ParsedEvent>` — Parse raw audit line to structured event
- `pub fn check_tamper_event(event: &ParsedEvent) -> Option<Alert>` — Check if event indicates tampering
- `pub fn event_to_alert(event: &ParsedEvent) -> Alert` — Convert parsed event to alert
- `pub fn parse_audit_line(line, watched_users) -> Option<Alert>` — One-shot parse audit line to alert
- `pub async fn tail_audit_log(...)` — Tail audit log file continuously
- `pub async fn tail_audit_log_with_behavior(...)` — Tail with behavioral analysis
- `pub async fn tail_audit_log_with_behavior_and_policy(...)` — Tail with behavioral analysis and policy engine

## src/behavior.rs

- `pub enum BehaviorCategory` — `DataExfiltration`, `PrivilegeEscalation`, `SecurityTamper`, `Reconnaissance`, `SideChannel`, `SecureClawMatch`
- `pub fn classify_behavior(event: &ParsedEvent) -> Option<(BehaviorCategory, Severity)>` — Classify event against ~200 behavioral patterns

## src/cognitive.rs

- `pub struct CognitiveBaseline` — Baseline hashes for AI identity files
- `pub struct CognitiveAlert` — Alert for cognitive file changes (`file`, `kind`, `watched`)
- `pub enum CognitiveAlertKind` — `Modified { diff }`, `Deleted`, `NewFile`
- `pub fn scan_cognitive_integrity(workspace_dir, baseline_path, secureclaw) -> Vec<ScanResult>` — Scan AI workspace files for integrity drift

## src/config.rs

- `pub struct Config` — Root configuration struct (all subsystem sections)
- `pub struct AutoUpdateConfig` — Auto-update settings (`enabled`, `interval`)
- `pub struct SshConfig` — SSH monitoring config (`enabled`)
- `pub struct PolicyConfig` — Policy engine config (`enabled`, `dir`)
- `pub struct GeneralConfig` — General settings (`watched_user`, `watched_users`, `watch_all_users`, `min_alert_level`, `log_file`)
- `pub struct SlackConfig` — Slack webhook settings (`enabled`, `webhook_url`, `backup_webhook_url`, `channel`, `min_slack_level`, `heartbeat_interval`)
- `pub struct AuditdConfig` — Auditd settings (`log_path`, `enabled`)
- `pub struct NetworkConfig` — Network monitoring settings (`log_path`, `log_prefix`, `enabled`, `source`, `allowlisted_cidrs`, `allowlisted_ports`)
- `pub fn default_allowlisted_cidrs() -> Vec<String>` — Default CIDR allowlist
- `pub fn default_allowlisted_ports() -> Vec<u16>` — Default port allowlist
- `pub struct FalcoConfig` — Falco integration settings (`enabled`, `log_path`)
- `pub struct SamhainConfig` — Samhain FIM settings (`enabled`, `log_path`)
- `pub struct ScansConfig` — Periodic scan settings (`interval`)
- `pub struct ApiConfig` — API server settings (`enabled`, `bind`, `port`)
- `pub struct ProxyConfig` — API key proxy settings (`enabled`, `bind`, `port`, `key_mapping`, `dlp`)
- `pub struct KeyMapping` — Virtual-to-real key mapping (`virtual_key`, `real`, `provider`, `upstream`)
- `pub struct DlpConfig` — DLP scanning config (`patterns`)
- `pub struct DlpPattern` — DLP pattern definition (`name`, `regex`, `action`)
- `pub struct NetPolicyConfig` — Network policy settings (`enabled`, `allowed_hosts`, `allowed_ports`, `blocked_hosts`, `mode`)
- `pub struct SentinelConfig` — Sentinel FIM settings (`enabled`, `watch_paths`, `quarantine_dir`, `shadow_dir`, `debounce_ms`, `scan_content`, `max_file_size_kb`)
- `pub struct WatchPathConfig` — Watch path entry (`path`, `patterns`, `policy`)
- `pub enum WatchPolicy` — `Protected`, `Watched`
- `pub struct OpenClawConfig` — OpenClaw integration settings

## src/config_merge.rs

- `pub fn merge_toml(base: &mut Value, overlay: Value)` — TOML overlay merge engine (deep-merges tables, replaces scalars)

## src/falco.rs

- `pub fn parse_falco_line(line: &str) -> Option<Alert>` — Parse Falco JSON alert line
- `pub async fn tail_falco_log(...)` — Tail Falco log file continuously

## src/firewall.rs

- `pub async fn monitor_firewall(tx: mpsc::Sender<Alert>)` — Monitor UFW firewall state changes (baseline + diff)

## src/journald.rs

- `pub fn journald_available() -> bool` — Check if journald is available on this system
- `pub async fn tail_journald_network(...)` — Monitor journald for network events
- `pub async fn tail_journald_ssh(tx: mpsc::Sender<Alert>) -> Result<()>` — Monitor journald for SSH events

## src/logtamper.rs

- `pub async fn monitor_log_integrity(...)` — Continuously monitor audit log for tampering
- `pub fn scan_audit_log_health(log_path: &Path) -> ScanResult` — One-shot audit log health check

## src/netpolicy.rs

- `pub struct NetPolicy` — Network policy enforcement engine (allowlist/blocklist)

## src/network.rs

- `pub fn parse_iptables_line(line: &str, prefix: &str) -> Option<Alert>` — Parse iptables/netfilter log line
- `pub struct NetworkAllowlist` — CIDR and port allowlist
- `pub async fn tail_network_log(...)` — Tail network log file continuously

## src/openclaw_config.rs

- `pub struct ConfigDrift` — Detected configuration drift entry
- `pub fn extract_security_fields(json_str: &str) -> HashMap<String, String>` — Extract security-relevant fields from OpenClaw config JSON
- `pub fn detect_drift(...)` — Compare current config against baseline for drift
- `pub fn load_baseline(path: &str) -> Option<HashMap<String, String>>` — Load saved config baseline from disk
- `pub fn save_baseline(path: &str, fields: &HashMap<String, String>) -> Result<()>` — Save config baseline to disk
- `pub fn scan_config_drift(config_path, baseline_path) -> Vec<ScanResult>` — Full config drift scan (load, compare, report)

## src/policy.rs

- `pub struct PolicyRule` — User-defined policy rule (`name`, `description`, `match_spec`, `action`, `enforcement`)
- `pub struct MatchSpec` — Policy match specification (`command`, `command_contains`, `file_access`, `exclude_args`)
- `pub struct PolicyVerdict` — Policy evaluation result (`rule_name`, `severity`, `message`)
- `pub struct PolicyEngine` — YAML-driven policy evaluation engine

## src/proxy.rs

- `pub struct ProxyServer` — API key vault proxy server
- `pub fn lookup_virtual_key<'a>(mapping, key) -> Option<(&str, &str, &str)>` — Resolve virtual key to real key + provider + upstream
- `pub fn scan_dlp(patterns, body) -> DlpResult` — Scan request/response body for sensitive data
- `pub enum DlpResult` — `Clean`, `Blocked(String)`, `Redacted(String)`

## src/samhain.rs

- `pub fn parse_samhain_line(line: &str) -> Option<Alert>` — Parse Samhain FIM log line
- `pub async fn tail_samhain_log(...)` — Tail Samhain log file continuously

## src/scanner.rs

- `pub enum ScanStatus` — `Pass`, `Warn`, `Fail`
- `pub struct ScanResult` — Scan check result (`category`, `status`, `details`, `timestamp`)
- `pub type SharedScanResults` — `Arc<Mutex<Vec<ScanResult>>>`
- `pub fn new_shared_scan_results() -> SharedScanResults` — Create shared scan results store
- `pub struct SecurityScanner` — Unit struct namespace for scan methods
- `pub fn scan_crontab_audit() -> ScanResult` — Audit crontab entries
- `pub fn scan_world_writable_files() -> ScanResult` — Find world-writable files
- `pub fn scan_suid_sgid_binaries() -> ScanResult` — Find SUID/SGID binaries
- `pub fn scan_kernel_modules() -> ScanResult` — Audit loaded kernel modules
- `pub fn scan_docker_security() -> ScanResult` — Check Docker daemon security
- `pub fn scan_password_policy() -> ScanResult` — Audit password policy settings
- `pub fn scan_open_file_descriptors() -> ScanResult` — Check open file descriptor limits
- `pub fn scan_dns_resolver() -> ScanResult` — Verify DNS resolver configuration
- `pub fn scan_ntp_sync() -> ScanResult` — Check NTP time synchronization
- `pub fn scan_failed_login_attempts() -> ScanResult` — Count recent failed logins
- `pub fn scan_zombie_processes() -> ScanResult` — Find zombie processes
- `pub fn scan_swap_tmpfs_security() -> ScanResult` — Check swap and tmpfs security
- `pub fn scan_environment_variables() -> ScanResult` — Audit environment variables
- `pub fn scan_package_integrity() -> ScanResult` — Verify package manager integrity
- `pub fn scan_core_dump_settings() -> ScanResult` — Check core dump configuration
- `pub fn scan_network_interfaces() -> ScanResult` — Audit network interfaces
- `pub fn scan_systemd_hardening() -> ScanResult` — Check systemd service hardening
- `pub fn scan_user_account_audit() -> ScanResult` — Audit user accounts
- `pub fn scan_firewall() -> ScanResult` — Check firewall status
- `pub fn parse_ufw_status(output: &str) -> ScanResult` — Parse UFW status output
- `pub fn scan_auditd() -> ScanResult` — Check auditd status
- `pub fn parse_auditctl_status(output: &str) -> ScanResult` — Parse auditctl status output
- `pub fn scan_integrity() -> ScanResult` — Check file integrity monitoring
- `pub fn scan_updates() -> ScanResult` — Check for available updates
- `pub fn scan_ssh() -> ScanResult` — Audit SSH configuration
- `pub fn scan_listening_services() -> ScanResult` — Audit listening network services
- `pub fn scan_resources() -> ScanResult` — Check system resource usage
- `pub fn scan_sidechannel_mitigations() -> ScanResult` — Verify side-channel attack mitigations
- `pub fn parse_disk_usage(output: &str) -> ScanResult` — Parse df output for disk usage
- `pub fn scan_user_persistence() -> Vec<ScanResult>` — Scan for user persistence mechanisms
- `pub fn scan_immutable_flags() -> ScanResult` — Check immutable file flags
- `pub fn check_lsattr_immutable(lsattr_output: &str) -> bool` — Parse lsattr output for immutable bit
- `pub fn scan_apparmor_protection() -> ScanResult` — Check AppArmor status
- `pub fn scan_secureclaw_sync() -> ScanResult` — Check SecureClaw pattern sync status
- `pub async fn run_periodic_scans(...)` — Main periodic scan loop

## src/secureclaw.rs

- `pub struct SecureClawConfig` — SecureClaw settings (`enabled`, `vendor_dir`)
- `pub struct SecureClawEngine` — Compiled vendor threat pattern engine (4 JSON databases)
- `pub struct CompiledPattern` — Compiled regex pattern (`name`, `category`, `regex`, `severity`, `action`)
- `pub struct PatternMatch` — Pattern match result (`pattern_name`, `category`, `matched_text`, `severity`, `action`)

## src/sentinel.rs

- `pub fn shadow_path_for(shadow_dir: &str, file_path: &str) -> PathBuf` — Compute shadow copy path
- `pub fn quarantine_path_for(quarantine_dir: &str, file_path: &str) -> PathBuf` — Compute quarantine path
- `pub fn generate_unified_diff(old: &str, new: &str, filename: &str) -> String` — Generate unified diff between two strings
- `pub fn is_log_rotation(file_path: &str) -> bool` — Detect if a file change is a log rotation
- `pub struct Sentinel` — Real-time file integrity monitor via inotify (quarantine/restore)

## src/slack.rs

- `pub struct SlackNotifier` — Slack webhook notification sender (primary + backup URLs)

## src/tui.rs

- `pub enum TuiEvent` — `Key(KeyEvent)`, `Tick`, `Alert(Alert)`, `ScanResults(Vec<ScanResult>)`
- `pub struct ConfigField` — Config editor field (`name`, `value`, `section`, `field_type`)
- `pub enum ConfigFocus` — `Sections`, `Fields`
- `pub enum FieldType` — `Text`, `Bool`, `Number`, `Select(Vec<String>)`
- `pub struct App` — TUI application state (tabs, alerts, scan results, config editor)
- `pub struct SudoPopup` — Sudo authentication popup state
- `pub enum SudoStatus` — `Idle`, `Waiting`, `Success`, `Failed(String)`
- `pub async fn run_tui(alert_rx, config_path) -> Result<()>` — Start terminal UI dashboard

## src/update.rs

- `pub fn run_update(args: &[String]) -> Result<()>` — Run self-update from GitHub releases (SHA-256 + Ed25519)
- `pub fn is_newer_version(current: &str, remote: &str) -> bool` — Compare semver versions
- `pub async fn run_auto_updater(alert_tx, interval_secs, mode)` — Background auto-update loop

## See Also

- [CLAUDE.md](../CLAUDE.md) — Full module guide with descriptions and usage patterns
- [ARCHITECTURE.md](ARCHITECTURE.md) — Module dependency graph and data flow
- [CONFIGURATION.md](CONFIGURATION.md) — Config struct field reference
