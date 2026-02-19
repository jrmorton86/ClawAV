// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Discord notification channel (stub).
//!
//! Discord bot integration is planned but not yet implemented. This module
//! provides a [`DiscordChannel`] that satisfies the [`NotificationChannel`]
//! trait contract but always reports itself as unavailable. The orchestrator
//! registers it and simply skips it when fanning out notifications.
//!
//! The stub also includes placeholder signature verification and interaction
//! parsing functions for the future Discord webhook endpoint.

use async_trait::async_trait;

use crate::approval::{ApprovalRequest, ApprovalResolution};
use crate::config::DiscordConfig;
use super::{Notification, NotificationChannel};

/// Stub Discord notification channel.
///
/// Always reports [`is_available`](NotificationChannel::is_available) as `false`.
/// All send methods are no-ops that return `Ok(())`.
pub struct DiscordChannel {
    enabled: bool,
}

impl DiscordChannel {
    /// Create a new Discord channel stub.
    ///
    /// The config is accepted for forward-compatibility but currently ignored
    /// since the channel is always unavailable.
    pub fn new(_config: &DiscordConfig) -> Self {
        Self { enabled: false }
    }
}

#[async_trait]
impl NotificationChannel for DiscordChannel {
    fn name(&self) -> &str {
        "discord"
    }

    fn is_available(&self) -> bool {
        // Stub: Discord integration is not yet implemented.
        false
    }

    async fn send_approval_request(&self, _request: &ApprovalRequest) -> anyhow::Result<()> {
        // No-op: Discord bot not yet implemented.
        Ok(())
    }

    async fn send_resolution(
        &self,
        _request: &ApprovalRequest,
        _resolution: &ApprovalResolution,
    ) -> anyhow::Result<()> {
        // No-op: Discord bot not yet implemented.
        Ok(())
    }

    async fn send_notification(&self, _notification: &Notification) -> anyhow::Result<()> {
        // No-op: Discord bot not yet implemented.
        Ok(())
    }
}

/// Verify a Discord interaction webhook signature.
///
/// This is a stub that always returns `false`. When the Discord bot is
/// implemented, this will use Ed25519 verification against the application
/// public key.
pub fn verify_discord_signature(
    _public_key: &str,
    _signature: &str,
    _timestamp: &str,
    _body: &str,
) -> bool {
    false // Not yet implemented
}

/// Parse a Discord interaction payload into an approval response.
///
/// This is a stub that always returns an error. When the Discord bot is
/// implemented, this will extract the request ID, approved/denied decision,
/// and the responding user from the interaction JSON.
///
/// # Returns
///
/// A tuple of `(request_id, approved, responder)` on success.
pub fn parse_discord_interaction(_body: &str) -> anyhow::Result<(String, bool, String)> {
    anyhow::bail!("Discord interactions not yet implemented")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use chrono::Utc;

    use crate::approval::ApprovalSource;
    use crate::core::alerts::Severity;

    /// Helper: create a test approval request.
    fn make_request() -> ApprovalRequest {
        ApprovalRequest::new(
            ApprovalSource::ClawSudo {
                policy_rule: Some("test-rule".to_string()),
            },
            "apt install curl".to_string(),
            "openclaw".to_string(),
            Severity::Warning,
            "test context".to_string(),
            Duration::from_secs(300),
        )
    }

    #[test]
    fn test_discord_channel_name() {
        let config = DiscordConfig::default();
        let channel = DiscordChannel::new(&config);
        assert_eq!(channel.name(), "discord");
    }

    #[test]
    fn test_discord_not_available() {
        let config = DiscordConfig::default();
        let channel = DiscordChannel::new(&config);
        assert!(!channel.is_available());
    }

    #[tokio::test]
    async fn test_discord_send_is_noop() {
        let config = DiscordConfig::default();
        let channel = DiscordChannel::new(&config);
        let request = make_request();
        let resolution = ApprovalResolution::Approved {
            by: "admin".to_string(),
            via: "discord".to_string(),
            message: None,
            at: Utc::now(),
        };

        channel
            .send_approval_request(&request)
            .await
            .expect("send_approval_request should succeed");

        channel
            .send_resolution(&request, &resolution)
            .await
            .expect("send_resolution should succeed");

        let notification = Notification::new(
            Severity::Warning,
            "Test notification".to_string(),
            "Test body".to_string(),
            "test".to_string(),
        );
        channel
            .send_notification(&notification)
            .await
            .expect("send_notification should succeed");
    }

    #[test]
    fn test_verify_discord_signature_always_false() {
        assert!(!verify_discord_signature("key", "sig", "ts", "body"));
    }

    #[test]
    fn test_parse_discord_interaction_always_errors() {
        let result = parse_discord_interaction("{}");
        assert!(result.is_err());
    }
}
