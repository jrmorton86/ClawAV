// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Notification channel abstraction layer.
//!
//! Defines [`NotificationChannel`], the trait that all notification backends
//! (Slack, Discord, TUI, system tray) implement, along with the
//! [`ChannelRegistry`] that owns the set of active channels.
//!
//! The [`Notification`] struct represents a generic one-way notification
//! (as opposed to approval requests, which are interactive).

pub mod discord;
pub mod tray;
pub mod tui;

use std::sync::Arc;

use async_trait::async_trait;
use serde::Serialize;

use crate::approval::{ApprovalRequest, ApprovalResolution};
use crate::core::alerts::Severity;

/// A notification channel capable of delivering approval requests, resolutions,
/// and one-way notifications to a human operator.
///
/// Implementations must be `Send + Sync` so they can be stored in an
/// `Arc<dyn NotificationChannel>` and shared across async tasks.
#[async_trait]
pub trait NotificationChannel: Send + Sync {
    /// Human-readable name for this channel (e.g., "slack", "tui", "discord").
    fn name(&self) -> &str;

    /// Returns `true` if the channel is currently reachable and configured.
    fn is_available(&self) -> bool;

    /// Deliver an approval request to the channel so a human can approve or deny.
    async fn send_approval_request(&self, request: &ApprovalRequest) -> anyhow::Result<()>;

    /// Notify the channel that a previously-sent approval request has been resolved.
    async fn send_resolution(
        &self,
        request: &ApprovalRequest,
        resolution: &ApprovalResolution,
    ) -> anyhow::Result<()>;

    /// Send a one-way informational notification (no response expected).
    async fn send_notification(&self, notification: &Notification) -> anyhow::Result<()>;
}

/// A one-way notification message (no approval/response expected).
///
/// Used for informational alerts, status updates, and system events that
/// should be pushed to all available channels.
#[derive(Debug, Clone, Serialize)]
pub struct Notification {
    /// How serious this notification is.
    pub severity: Severity,
    /// Short summary line.
    pub title: String,
    /// Longer descriptive body.
    pub body: String,
    /// Which subsystem generated this notification (e.g., "scanner", "sentinel").
    pub source: String,
}

impl Notification {
    /// Create a new notification.
    pub fn new(severity: Severity, title: String, body: String, source: String) -> Self {
        Self {
            severity,
            title,
            body,
            source,
        }
    }
}

/// Registry of all configured notification channels.
///
/// Owned by the [`ApprovalOrchestrator`](crate::approval) and used to fan out
/// approval requests and notifications to every registered backend.
pub struct ChannelRegistry {
    channels: Vec<Arc<dyn NotificationChannel>>,
}

impl ChannelRegistry {
    /// Create an empty registry with no channels.
    pub fn new() -> Self {
        Self {
            channels: Vec::new(),
        }
    }

    /// Register a new notification channel.
    pub fn register(&mut self, channel: Arc<dyn NotificationChannel>) {
        self.channels.push(channel);
    }

    /// Return only channels that report themselves as currently available.
    pub fn available(&self) -> Vec<&Arc<dyn NotificationChannel>> {
        self.channels.iter().filter(|ch| ch.is_available()).collect()
    }

    /// Return all registered channels regardless of availability.
    pub fn all(&self) -> &[Arc<dyn NotificationChannel>] {
        &self.channels
    }

    /// Return the number of registered channels.
    pub fn len(&self) -> usize {
        self.channels.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal mock channel for testing the registry.
    struct MockChannel {
        channel_name: String,
        available: bool,
    }

    impl MockChannel {
        fn new(name: &str, available: bool) -> Self {
            Self {
                channel_name: name.to_string(),
                available,
            }
        }
    }

    #[async_trait]
    impl NotificationChannel for MockChannel {
        fn name(&self) -> &str {
            &self.channel_name
        }

        fn is_available(&self) -> bool {
            self.available
        }

        async fn send_approval_request(&self, _request: &ApprovalRequest) -> anyhow::Result<()> {
            Ok(())
        }

        async fn send_resolution(
            &self,
            _request: &ApprovalRequest,
            _resolution: &ApprovalResolution,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        async fn send_notification(&self, _notification: &Notification) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_channel_registry_filters_unavailable() {
        let mut registry = ChannelRegistry::new();
        registry.register(Arc::new(MockChannel::new("slack", true)));
        registry.register(Arc::new(MockChannel::new("discord", false)));
        registry.register(Arc::new(MockChannel::new("tui", true)));

        assert_eq!(registry.len(), 3);

        let available = registry.available();
        assert_eq!(available.len(), 2);
        assert_eq!(available[0].name(), "slack");
        assert_eq!(available[1].name(), "tui");
    }

    #[test]
    fn test_notification_creation() {
        let notif = Notification::new(
            Severity::Warning,
            "Disk usage high".to_string(),
            "/var/log is at 92% capacity".to_string(),
            "scanner".to_string(),
        );

        assert_eq!(notif.severity, Severity::Warning);
        assert_eq!(notif.title, "Disk usage high");
        assert_eq!(notif.body, "/var/log is at 92% capacity");
        assert_eq!(notif.source, "scanner");
    }

    #[test]
    fn test_empty_registry() {
        let registry = ChannelRegistry::new();
        assert_eq!(registry.len(), 0);
        assert!(registry.available().is_empty());
        assert!(registry.all().is_empty());
    }
}
