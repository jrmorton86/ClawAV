use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;
use crate::secureclaw::SecureClawConfig;

#[derive(Debug, Deserialize, Clone)]
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
}

#[derive(Debug, Deserialize, Clone)]
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

#[derive(Debug, Deserialize, Clone)]
pub struct GeneralConfig {
    pub watched_user: Option<String>,  // Keep for backward compat
    #[serde(default)]
    pub watched_users: Vec<String>,
    #[serde(default)]
    pub watch_all_users: bool,
    pub min_alert_level: String,
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

#[derive(Debug, Deserialize, Clone)]
pub struct SlackConfig {
    pub enabled: Option<bool>,
    pub webhook_url: String,
    #[serde(default)]
    pub backup_webhook_url: String,
    pub channel: String,
    pub min_slack_level: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuditdConfig {
    pub log_path: String,
    pub enabled: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NetworkConfig {
    pub log_path: String,
    pub log_prefix: String,
    pub enabled: bool,
    #[serde(default = "default_network_source")]
    pub source: String,
}

fn default_network_source() -> String {
    "auto".to_string()
}

#[derive(Debug, Deserialize, Clone)]
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

#[derive(Debug, Deserialize, Clone)]
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

#[derive(Debug, Deserialize, Clone)]
pub struct ScansConfig {
    pub interval: u64,
}

#[derive(Debug, Deserialize, Clone)]
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

#[derive(Debug, Deserialize, Clone)]
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

#[derive(Debug, Deserialize, Clone)]
pub struct KeyMapping {
    #[serde(alias = "virtual")]
    pub virtual_key: String,
    pub real: String,
    pub provider: String,
    pub upstream: String,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct DlpConfig {
    #[serde(default)]
    pub patterns: Vec<DlpPattern>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DlpPattern {
    pub name: String,
    pub regex: String,
    pub action: String,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config: {}", path.display()))?;
        let config: Config = toml::from_str(&content)
            .with_context(|| "Failed to parse config")?;
        Ok(config)
    }
}
