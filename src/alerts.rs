// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Core alert types shared across all ClawTower modules.
//!
//! Every monitoring subsystem produces [`Alert`] values with a [`Severity`] level,
//! source tag, and human-readable message. These flow through the aggregator pipeline
//! to the TUI, Slack, API, and audit chain.

use chrono::{DateTime, Local};
use serde::Serialize;
use std::fmt;

/// Alert severity level, ordered from lowest to highest.
///
/// Used for filtering (e.g., minimum Slack notification level) and display styling.
/// Implements `Ord` so `Critical > Warning > Info`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Warning => write!(f, "WARN"),
            Severity::Critical => write!(f, "CRIT"),
        }
    }
}

impl Severity {
    /// Parse a severity from a case-insensitive string. Defaults to `Info` for unrecognized values.
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" | "crit" => Severity::Critical,
            "warning" | "warn" => Severity::Warning,
            _ => Severity::Info,
        }
    }

    /// Returns the emoji icon for this severity (used in Slack messages and TUI).
    pub fn emoji(&self) -> &str {
        match self {
            Severity::Info => "ℹ️",
            Severity::Warning => "⚠️",
            Severity::Critical => "🔴",
        }
    }
}

/// A timestamped security alert from any monitoring source.
///
/// Alerts are the universal currency of ClawTower — every module produces them,
/// the aggregator filters them, and consumers (TUI, Slack, API) display them.
#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    /// When the alert was created (local time)
    pub timestamp: DateTime<Local>,
    /// How serious this alert is
    pub severity: Severity,
    /// Which module generated it (e.g., "auditd", "behavior", "scan:firewall")
    pub source: String,
    /// Human-readable description of what happened
    pub message: String,
    /// Name of the AI agent that triggered this alert (if known)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
    /// Name of the skill/tool that triggered this alert (if known)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skill_name: Option<String>,
    /// Version of the IOC database that triggered this alert (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ioc_version: Option<String>,
}

impl Alert {
    /// Create a new alert timestamped to now.
    pub fn new(severity: Severity, source: &str, message: &str) -> Self {
        Self {
            timestamp: Local::now(),
            severity,
            source: source.to_string(),
            message: message.to_string(),
            agent_name: None,
            skill_name: None,
            ioc_version: None,
        }
    }

    /// Attach an agent name to this alert.
    pub fn with_agent(mut self, agent: &str) -> Self {
        self.agent_name = Some(agent.to_string());
        self
    }

    /// Attach a skill name to this alert.
    pub fn with_skill(mut self, skill: &str) -> Self {
        self.skill_name = Some(skill.to_string());
        self
    }

    /// Attach the IOC database version that triggered this alert.
    pub fn with_ioc_version(mut self, version: &str) -> Self {
        self.ioc_version = Some(version.to_string());
        self
    }
}

impl fmt::Display for Alert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} [{}] {}",
            self.timestamp.format("%H:%M:%S"),
            self.severity,
            self.source,
            self.message
        )?;
        if let Some(ref agent) = self.agent_name {
            write!(f, " (agent: {})", agent)?;
        }
        if let Some(ref skill) = self.skill_name {
            write!(f, " (skill: {})", skill)?;
        }
        Ok(())
    }
}

/// Bounded ring buffer of alerts for the TUI dashboard.
///
/// When full, the oldest alert is evicted to make room. This keeps memory
/// usage constant regardless of uptime.
pub struct AlertStore {
    alerts: Vec<Alert>,
    max_size: usize,
}

impl AlertStore {
    pub fn new(max_size: usize) -> Self {
        Self {
            alerts: Vec::with_capacity(max_size),
            max_size,
        }
    }

    /// Add an alert, evicting the oldest if at capacity.
    pub fn push(&mut self, alert: Alert) {
        if self.alerts.len() >= self.max_size {
            self.alerts.remove(0);
        }
        self.alerts.push(alert);
    }

    /// Returns all stored alerts in chronological order.
    pub fn alerts(&self) -> &[Alert] {
        &self.alerts
    }

    /// Count alerts matching a given severity level.
    pub fn count_by_severity(&self, severity: &Severity) -> usize {
        self.alerts.iter().filter(|a| &a.severity == severity).count()
    }

    /// Count alerts matching a given source string.
    #[allow(dead_code)]
    pub fn count_by_source(&self, source: &str) -> usize {
        self.alerts.iter().filter(|a| a.source == source).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_new_no_attribution() {
        let alert = Alert::new(Severity::Info, "test", "hello");
        assert!(alert.agent_name.is_none());
        assert!(alert.skill_name.is_none());
    }

    #[test]
    fn test_alert_with_agent() {
        let alert = Alert::new(Severity::Warning, "behavior", "exfil detected")
            .with_agent("openclaw");
        assert_eq!(alert.agent_name, Some("openclaw".to_string()));
        assert!(alert.skill_name.is_none());
    }

    #[test]
    fn test_alert_with_skill() {
        let alert = Alert::new(Severity::Info, "proxy", "request blocked")
            .with_skill("web-search");
        assert!(alert.agent_name.is_none());
        assert_eq!(alert.skill_name, Some("web-search".to_string()));
    }

    #[test]
    fn test_alert_with_both() {
        let alert = Alert::new(Severity::Critical, "behavior", "lateral movement")
            .with_agent("openclaw")
            .with_skill("shell-exec");
        assert_eq!(alert.agent_name, Some("openclaw".to_string()));
        assert_eq!(alert.skill_name, Some("shell-exec".to_string()));
    }

    #[test]
    fn test_alert_display_no_attribution() {
        let alert = Alert::new(Severity::Info, "test", "no agent");
        let output = format!("{}", alert);
        assert!(!output.contains("(agent:"));
        assert!(!output.contains("(skill:"));
        assert!(output.contains("[test]"));
        assert!(output.contains("no agent"));
    }

    #[test]
    fn test_alert_display_with_attribution() {
        let alert = Alert::new(Severity::Warning, "behavior", "suspicious")
            .with_agent("openclaw")
            .with_skill("web-search");
        let output = format!("{}", alert);
        assert!(output.contains("(agent: openclaw)"));
        assert!(output.contains("(skill: web-search)"));
    }

    #[test]
    fn test_alert_with_ioc_version() {
        let alert = Alert::new(Severity::Critical, "barnacle", "test")
            .with_ioc_version("1.2.3");
        assert_eq!(alert.ioc_version, Some("1.2.3".to_string()));
    }

    #[test]
    fn test_alert_ioc_version_default_none() {
        let alert = Alert::new(Severity::Info, "test", "no version");
        assert!(alert.ioc_version.is_none());
    }
}
