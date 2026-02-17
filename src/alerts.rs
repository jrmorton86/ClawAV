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
}

impl Alert {
    /// Create a new alert timestamped to now.
    pub fn new(severity: Severity, source: &str, message: &str) -> Self {
        Self {
            timestamp: Local::now(),
            severity,
            source: source.to_string(),
            message: message.to_string(),
        }
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
        )
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
    pub fn count_by_source(&self, source: &str) -> usize {
        self.alerts.iter().filter(|a| a.source == source).count()
    }
}
