//! Configuration loading and serialization.
//!
//! Defines the TOML configuration schema for ClawAV. The root [`Config`] struct
//! contains sections for each subsystem (auditd, network, falco, samhain, proxy,
//! policy, secureclaw, sentinel, etc.).
//!
//! All sections implement `Default` and `serde::Deserialize` with `#[serde(default)]`
//! so missing fields gracefully fall back to sensible defaults. Config is loaded
//! from `/etc/clawav/config.toml` by default.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use crate::secureclaw::SecureClawConfig;

/// Root configuration struct, deserialized from TOML.
///
/// All subsystem sections use `#[serde(default)]` so missing sections
/// gracefully use defaults. Load with [`Config::load`], save with [`Config::save`].
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Config {
    pub general: GeneralConfig,
    pub slack: SlackConfig,
    pub auditd: AuditdConfig,
    pub network: NetworkConfig,
    #[serde(default)]
    pub falco: FalcoConfig,
    #[serde(default)]
    pub samhain: SamhainConfig,
    #[serde(default)]
    pub api: ApiConfig,
    pub scans: ScansConfig,
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub secureclaw: SecureClawConfig,
    #[serde(default)]
    pub netpolicy: NetPolicyConfig,
    #[serde(default)]
    pub ssh: SshConfig,
    #[serde(default)]
    pub sentinel: SentinelConfig,
    #[serde(default)]
    pub auto_update: AutoUpdateConfig,
    #[serde(default)]
    pub openclaw: OpenClawConfig,
}

/// Auto-update configuration: checks GitHub releases periodically.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AutoUpdateConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_auto_update_interval")]
    pub interval: u64,
    #[serde(default = "default_auto_update_mode")]
    pub mode: String,
}

fn default_auto_update_interval() -> u64 { 300 }
fn default_auto_update_mode() -> String { "auto".to_string() }

impl Default for AutoUpdateConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: 300,
            mode: "auto".to_string(),
        }
    }
}

/// SSH login monitoring configuration.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SshConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
}
fn default_true() -> bool { true }
impl Default for SshConfig {
    fn default() -> Self { Self { enabled: true } }
}

/// YAML policy engine configuration.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PolicyConfig {
    pub enabled: bool,
    pub dir: String,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dir: "./policies".to_string(),
        }
    }
}

/// General configuration: which users to monitor, alert level, log path.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct GeneralConfig {
    /// Single watched user (backward compat, prefer `watched_users`)
    pub watched_user: Option<String>,
    /// List of UIDs to monitor; empty + watch_all_users=false means watch all
    #[serde(default)]
    pub watched_users: Vec<String>,
    /// If true, monitor all users regardless of watched_users
    #[serde(default)]
    pub watch_all_users: bool,
    /// Minimum severity for alerts ("info", "warning", "critical")
    pub min_alert_level: String,
    /// Path to ClawAV's own log file
    pub log_file: String,
}

impl GeneralConfig {
    /// Returns the effective set of watched users, handling backward compat
    pub fn effective_watched_users(&self) -> Option<Vec<String>> {
        if self.watch_all_users {
            return None; // None means watch all
        }
        let mut users = self.watched_users.clone();
        if let Some(ref single) = self.watched_user {
            if !users.contains(single) {
                users.push(single.clone());
            }
        }
        if users.is_empty() {
            None // No users specified = watch all
        } else {
            Some(users)
        }
    }
}

/// Slack notification configuration.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SlackConfig {
    /// Explicitly enable/disable Slack (None = enabled if webhook_url is set)
    pub enabled: Option<bool>,
    /// Primary incoming webhook URL
    pub webhook_url: String,
    /// Failover webhook URL if primary fails
    #[serde(default)]
    pub backup_webhook_url: String,
    /// Slack channel name
    pub channel: String,
    /// Minimum severity to forward to Slack
    pub min_slack_level: String,
    /// Interval in seconds for periodic health heartbeat to Slack (0 = disabled)
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval: u64,
}

fn default_heartbeat_interval() -> u64 {
    3600
}

/// Auditd log monitoring configuration.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AuditdConfig {
    pub log_path: String,
    pub enabled: bool,
}

/// Network (iptables/netfilter) log monitoring configuration.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NetworkConfig {
    pub log_path: String,
    pub log_prefix: String,
    pub enabled: bool,
    #[serde(default = "default_network_source")]
    pub source: String,
    /// CIDR ranges to never alert on
    #[serde(default = "default_allowlisted_cidrs")]
    pub allowlisted_cidrs: Vec<String>,
    /// Extra ports to never alert on
    #[serde(default = "default_allowlisted_ports")]
    pub allowlisted_ports: Vec<u16>,
}

fn default_network_source() -> String {
    "auto".to_string()
}

/// Default CIDR ranges that are never alerted on (RFC1918, multicast, loopback).
pub fn default_allowlisted_cidrs() -> Vec<String> {
    vec![
        "192.168.0.0/16".to_string(),
        "10.0.0.0/8".to_string(),
        "172.16.0.0/12".to_string(),
        "169.254.0.0/16".to_string(),
        "127.0.0.0/8".to_string(),
        "224.0.0.0/4".to_string(),
    ]
}

/// Default ports that are never alerted on (HTTPS, DNS, NTP, mDNS).
pub fn default_allowlisted_ports() -> Vec<u16> {
    vec![443, 53, 123, 5353]
}

/// Falco eBPF integration configuration.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FalcoConfig {
    pub enabled: bool,
    pub log_path: String,
}

impl Default for FalcoConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            log_path: "/var/log/falco/falco_output.jsonl".to_string(),
        }
    }
}

/// Samhain file integrity monitoring integration configuration.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SamhainConfig {
    pub enabled: bool,
    pub log_path: String,
}

impl Default for SamhainConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            log_path: "/var/log/samhain/samhain.log".to_string(),
        }
    }
}

/// Periodic security scanner configuration.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ScansConfig {
    /// Interval between scan cycles in seconds
    pub interval: u64,
}

/// HTTP REST API server configuration.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ApiConfig {
    pub enabled: bool,
    pub bind: String,
    pub port: u16,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "0.0.0.0".to_string(),
            port: 18791,
        }
    }
}

/// API key vault proxy configuration.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ProxyConfig {
    pub enabled: bool,
    pub bind: String,
    pub port: u16,
    #[serde(default)]
    pub key_mapping: Vec<KeyMapping>,
    #[serde(default)]
    pub dlp: DlpConfig,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "127.0.0.1".to_string(),
            port: 18790,
            key_mapping: Vec::new(),
            dlp: DlpConfig::default(),
        }
    }
}

/// Maps a virtual API key to a real key for a specific provider/upstream.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct KeyMapping {
    #[serde(alias = "virtual")]
    pub virtual_key: String,
    pub real: String,
    pub provider: String,
    pub upstream: String,
}

/// Data Loss Prevention pattern configuration for the proxy.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct DlpConfig {
    #[serde(default)]
    pub patterns: Vec<DlpPattern>,
}

/// A single DLP regex pattern with a name and action (block or redact).
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DlpPattern {
    pub name: String,
    pub regex: String,
    pub action: String,
}

/// Network policy (allowlist/blocklist) configuration.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NetPolicyConfig {
    pub enabled: bool,
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    #[serde(default)]
    pub allowed_ports: Vec<u16>,
    #[serde(default)]
    pub blocked_hosts: Vec<String>,
    #[serde(default = "default_netpolicy_mode")]
    pub mode: String,
}

fn default_netpolicy_mode() -> String {
    "blocklist".to_string()
}

impl Default for NetPolicyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_hosts: Vec::new(),
            allowed_ports: vec![80, 443, 53],
            blocked_hosts: Vec::new(),
            mode: "blocklist".to_string(),
        }
    }
}

/// Real-time file sentinel configuration.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SentinelConfig {
    #[serde(default = "default_sentinel_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub watch_paths: Vec<WatchPathConfig>,
    #[serde(default = "default_quarantine_dir")]
    pub quarantine_dir: String,
    #[serde(default = "default_shadow_dir")]
    pub shadow_dir: String,
    #[serde(default = "default_debounce_ms")]
    pub debounce_ms: u64,
    #[serde(default = "default_scan_content")]
    pub scan_content: bool,
    #[serde(default = "default_max_file_size_kb")]
    pub max_file_size_kb: u64,
    /// Glob patterns for paths excluded from content scanning (e.g. credential
    /// stores that legitimately contain API keys). Matched using `glob::Pattern`.
    #[serde(default = "default_content_scan_excludes")]
    pub content_scan_excludes: Vec<String>,
    /// Substring patterns for paths excluded from content scanning.
    /// If a file's path contains any of these strings, SecureClaw content
    /// scanning is skipped (change detection still applies).
    #[serde(default = "default_exclude_content_scan")]
    pub exclude_content_scan: Vec<String>,
}

/// A single path to watch with its glob patterns and policy.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct WatchPathConfig {
    pub path: String,
    pub patterns: Vec<String>,
    pub policy: WatchPolicy,
}

/// Policy for a watched path: Protected files are quarantined+restored on change;
/// Watched files are allowed to change with shadow updates.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum WatchPolicy {
    Protected,
    Watched,
}

fn default_sentinel_enabled() -> bool { true }
fn default_quarantine_dir() -> String { "/etc/clawav/quarantine".to_string() }
fn default_shadow_dir() -> String { "/etc/clawav/sentinel-shadow".to_string() }
fn default_debounce_ms() -> u64 { 200 }
fn default_scan_content() -> bool { true }
fn default_max_file_size_kb() -> u64 { 1024 }

/// Default paths excluded from content scanning. These are files that
/// legitimately contain API keys or credentials and should not be flagged
/// by SecureClaw pattern matching.
fn default_content_scan_excludes() -> Vec<String> {
    vec![
        "**/.openclaw/**/auth-profiles.json".to_string(),
        "**/.openclaw/credentials/**".to_string(),
        "**/superpowers/skills/**".to_string(),
    ]
}

/// Default paths excluded from content scanning via simple substring matching.
/// This is a secondary exclusion mechanism — files whose path contains any of
/// these substrings will skip SecureClaw content scanning even if they are
/// Protected policy.
fn default_exclude_content_scan() -> Vec<String> {
    vec![
        "superpowers/skills".to_string(),
    ]
}

impl Default for SentinelConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            watch_paths: vec![
                WatchPathConfig {
                    path: "/home/openclaw/.openclaw/workspace/SOUL.md".to_string(),
                    patterns: vec!["*".to_string()],
                    policy: WatchPolicy::Protected,
                },
                WatchPathConfig {
                    path: "/home/openclaw/.openclaw/workspace/AGENTS.md".to_string(),
                    patterns: vec!["*".to_string()],
                    policy: WatchPolicy::Protected,
                },
                WatchPathConfig {
                    path: "/home/openclaw/.openclaw/workspace/MEMORY.md".to_string(),
                    patterns: vec!["*".to_string()],
                    policy: WatchPolicy::Watched,
                },
                WatchPathConfig {
                    path: "/home/openclaw/.openclaw/workspace/IDENTITY.md".to_string(),
                    patterns: vec!["*".to_string()],
                    policy: WatchPolicy::Protected,
                },
                WatchPathConfig {
                    path: "/home/openclaw/.openclaw/workspace/USER.md".to_string(),
                    patterns: vec!["*".to_string()],
                    policy: WatchPolicy::Protected,
                },
                WatchPathConfig {
                    path: "/home/openclaw/.openclaw/workspace/HEARTBEAT.md".to_string(),
                    patterns: vec!["*".to_string()],
                    policy: WatchPolicy::Watched,
                },
                WatchPathConfig {
                    path: "/home/openclaw/.openclaw/workspace/TOOLS.md".to_string(),
                    patterns: vec!["*".to_string()],
                    policy: WatchPolicy::Watched,
                },
                WatchPathConfig {
                    path: "/home/openclaw/.openclaw/workspace/superpowers/skills".to_string(),
                    patterns: vec!["SKILL.md".to_string()],
                    policy: WatchPolicy::Watched,
                },
                // OpenClaw credential and config monitoring
                WatchPathConfig {
                    path: "/home/openclaw/.openclaw/openclaw.json".to_string(),
                    patterns: vec!["*".to_string()],
                    policy: WatchPolicy::Watched,
                },
                WatchPathConfig {
                    path: "/home/openclaw/.openclaw/credentials".to_string(),
                    patterns: vec!["*.json".to_string()],
                    policy: WatchPolicy::Protected,
                },
                WatchPathConfig {
                    path: "/home/openclaw/.openclaw/agents/main/agent/auth-profiles.json".to_string(),
                    patterns: vec!["*".to_string()],
                    policy: WatchPolicy::Protected,
                },
                // Session metadata monitoring
                WatchPathConfig {
                    path: "/home/openclaw/.openclaw/agents/main/sessions/sessions.json".to_string(),
                    patterns: vec!["*".to_string()],
                    policy: WatchPolicy::Watched,
                },
                // WhatsApp credential theft detection
                WatchPathConfig {
                    path: "/home/openclaw/.openclaw/credentials/whatsapp".to_string(),
                    patterns: vec!["creds.json".to_string()],
                    policy: WatchPolicy::Protected,
                },
                // Pairing allowlist changes
                WatchPathConfig {
                    path: "/home/openclaw/.openclaw/credentials".to_string(),
                    patterns: vec!["*-allowFrom.json".to_string()],
                    policy: WatchPolicy::Watched,
                },
            ],
            quarantine_dir: default_quarantine_dir(),
            shadow_dir: default_shadow_dir(),
            debounce_ms: default_debounce_ms(),
            scan_content: default_scan_content(),
            max_file_size_kb: default_max_file_size_kb(),
            content_scan_excludes: default_content_scan_excludes(),
            exclude_content_scan: default_exclude_content_scan(),
        }
    }
}

/// OpenClaw-specific security monitoring configuration.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OpenClawConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_openclaw_config_path")]
    pub config_path: String,
    #[serde(default = "default_openclaw_state_dir")]
    pub state_dir: String,
    #[serde(default = "default_openclaw_audit_cmd")]
    pub audit_command: String,
    #[serde(default = "default_true")]
    pub audit_on_scan: bool,
    #[serde(default = "default_true")]
    pub config_drift_check: bool,
    #[serde(default = "default_openclaw_baseline_path")]
    pub baseline_path: String,
    #[serde(default)]
    pub mdns_check: bool,
    #[serde(default)]
    pub plugin_watch: bool,
    #[serde(default)]
    pub session_log_audit: bool,
}

fn default_openclaw_config_path() -> String { "/home/openclaw/.openclaw/openclaw.json".to_string() }
fn default_openclaw_state_dir() -> String { "/home/openclaw/.openclaw".to_string() }
fn default_openclaw_audit_cmd() -> String { "openclaw security audit --deep".to_string() }
fn default_openclaw_baseline_path() -> String { "/etc/clawav/openclaw-config-baseline.json".to_string() }

impl Default for OpenClawConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            config_path: default_openclaw_config_path(),
            state_dir: default_openclaw_state_dir(),
            audit_command: default_openclaw_audit_cmd(),
            audit_on_scan: true,
            config_drift_check: true,
            baseline_path: default_openclaw_baseline_path(),
            mdns_check: false,
            plugin_watch: false,
            session_log_audit: false,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config: {}", path.display()))?;
        let config: Config = toml::from_str(&content)
            .with_context(|| "Failed to parse config")?;
        Ok(config)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .with_context(|| "Failed to serialize config")?;
        std::fs::write(path, content)
            .with_context(|| format!("Failed to write config: {}", path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openclaw_config_defaults() {
        let config: OpenClawConfig = toml::from_str("").unwrap();
        assert!(config.enabled);
        assert_eq!(config.state_dir, "/home/openclaw/.openclaw");
        assert!(config.audit_on_scan);
        assert!(config.config_drift_check);
    }

    #[test]
    fn test_openclaw_config_custom() {
        let toml_str = r#"
            enabled = false
            config_path = "/tmp/test.json"
            state_dir = "/tmp/openclaw"
            audit_on_scan = false
        "#;
        let config: OpenClawConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.enabled);
        assert_eq!(config.config_path, "/tmp/test.json");
        assert!(!config.audit_on_scan);
    }

    #[test]
    fn test_default_sentinel_includes_openclaw_creds() {
        let config = SentinelConfig::default();
        let paths: Vec<&str> = config.watch_paths.iter()
            .map(|w| w.path.as_str()).collect();
        assert!(paths.iter().any(|p| p.contains(".openclaw/credentials")),
            "Should watch OpenClaw credentials dir");
        assert!(paths.iter().any(|p| p.contains("openclaw.json")),
            "Should watch OpenClaw config file");
        assert!(paths.iter().any(|p| p.contains("auth-profiles.json")),
            "Should watch auth profiles");
    }

    #[test]
    fn test_default_sentinel_content_scan_excludes_openclaw_auth() {
        let config = SentinelConfig::default();
        assert!(!config.content_scan_excludes.is_empty(),
            "Should have default content scan exclusions");
        assert!(config.content_scan_excludes.iter().any(|p| p.contains("auth-profiles.json")),
            "Should exclude OpenClaw auth-profiles.json from content scanning");
        assert!(config.content_scan_excludes.iter().any(|p| p.contains(".openclaw/credentials")),
            "Should exclude OpenClaw credentials dir from content scanning");
    }

    #[test]
    fn test_default_sentinel_includes_openclaw_session_and_whatsapp() {
        let config = SentinelConfig::default();
        let paths: Vec<&str> = config.watch_paths.iter()
            .map(|w| w.path.as_str()).collect();
        assert!(paths.iter().any(|p| p.contains("sessions/sessions.json")),
            "Should watch session metadata");
        assert!(paths.iter().any(|p| p.contains("credentials/whatsapp")),
            "Should watch WhatsApp credentials");
    }

    #[test]
    fn test_exclude_content_scan_pattern() {
        let config = SentinelConfig::default();
        assert!(!config.exclude_content_scan.is_empty(),
            "Should have default exclude_content_scan patterns");

        let path = "/home/openclaw/.openclaw/workspace/superpowers/skills/brainstorming/SKILL.md";
        let excluded = config.exclude_content_scan.iter().any(|excl| path.contains(excl));
        assert!(excluded, "Skills directory should be excluded from content scan");

        let path2 = "/home/openclaw/.openclaw/workspace/SOUL.md";
        let excluded2 = config.exclude_content_scan.iter().any(|excl| path2.contains(excl));
        assert!(!excluded2, "SOUL.md should NOT be excluded from content scan");
    }
}
