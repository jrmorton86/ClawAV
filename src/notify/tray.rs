// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! System tray notification channel.
//!
//! This is a thin "signal" channel that tells the approval orchestrator a
//! desktop operator may be watching for approval requests via the system tray.
//!
//! The actual desktop notification logic lives in the `clawtower-tray` binary,
//! which already polls the ClawTower HTTP API every 10 seconds. Once the
//! approval API endpoints are available (Task 6), the tray binary will
//! automatically discover pending approvals and present `notify-rust` desktop
//! notifications with approve/deny action buttons.
//!
//! Because `clawtower-tray` drives its own polling loop, this channel's send
//! methods are intentional no-ops. Its primary value is reporting
//! [`is_available`](NotificationChannel::is_available) so the orchestrator
//! knows that at least one human-facing channel is configured.

use async_trait::async_trait;

use crate::approval::{ApprovalRequest, ApprovalResolution};
use crate::config::TrayConfig;
use super::{Notification, NotificationChannel};

/// Notification channel backed by the system tray polling loop.
///
/// All send methods are no-ops because the tray binary independently polls the
/// approval API. This channel exists to signal availability to the orchestrator.
pub struct TrayChannel {
    enabled: bool,
    notifications: bool,
    #[allow(dead_code)]
    approval_actions: bool,
}

impl TrayChannel {
    /// Create a new tray channel from the tray configuration section.
    pub fn new(config: &TrayConfig) -> Self {
        Self {
            enabled: config.enabled,
            notifications: config.notifications,
            approval_actions: config.approval_actions,
        }
    }
}

#[async_trait]
impl NotificationChannel for TrayChannel {
    fn name(&self) -> &str {
        "tray"
    }

    fn is_available(&self) -> bool {
        self.enabled && self.notifications
    }

    async fn send_approval_request(&self, _request: &ApprovalRequest) -> anyhow::Result<()> {
        // No-op: the tray binary polls /api/approvals and will see pending requests.
        Ok(())
    }

    async fn send_resolution(
        &self,
        _request: &ApprovalRequest,
        _resolution: &ApprovalResolution,
    ) -> anyhow::Result<()> {
        // No-op: the tray binary polls for updated approval state.
        Ok(())
    }

    async fn send_notification(&self, _notification: &Notification) -> anyhow::Result<()> {
        // No-op: the tray binary receives alerts via its own API polling loop.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tray_channel_name() {
        let config = TrayConfig::default();
        let channel = TrayChannel::new(&config);
        assert_eq!(channel.name(), "tray");
    }

    #[test]
    fn test_tray_available_when_enabled() {
        let config = TrayConfig {
            enabled: true,
            notifications: true,
            approval_actions: true,
        };
        let channel = TrayChannel::new(&config);
        assert!(channel.is_available());
    }

    #[test]
    fn test_tray_not_available_when_disabled() {
        let config = TrayConfig {
            enabled: false,
            notifications: true,
            approval_actions: true,
        };
        let channel = TrayChannel::new(&config);
        assert!(!channel.is_available());
    }

    #[test]
    fn test_tray_not_available_when_notifications_off() {
        let config = TrayConfig {
            enabled: true,
            notifications: false,
            approval_actions: true,
        };
        let channel = TrayChannel::new(&config);
        assert!(!channel.is_available());
    }
}
