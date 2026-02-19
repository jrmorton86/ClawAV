// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Admin socket and key management for authenticated ClawTower control.
//!
//! Provides a Unix domain socket (`/var/run/clawtower/admin.sock`) that accepts
//! JSON commands authenticated with an Argon2-hashed admin key. The key is
//! generated once during `clawtower harden` (via `generate-key` subcommand),
//! displayed to the operator, and never stored — only the Argon2 hash is persisted.
//!
//! Supported commands: `status`, `scan`, `pause`, `config-update`.
//! Failed auth triggers rate limiting (3 failures → 1-hour lockout) and
//! Critical-severity alerts.

use anyhow::{Context, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::{mpsc, Mutex};

use crate::alerts::{Alert, Severity};

const KEY_PREFIX: &str = "OCAV-";
const KEY_BYTES: usize = 32; // 256 bits
const MAX_FAILURES: u32 = 3;
const LOCKOUT_DURATION: Duration = Duration::from_secs(3600); // 1 hour
const MAX_PAUSE_MINUTES: u64 = 30;

/// JSON request sent by clients over the admin socket.
#[derive(Debug, Deserialize)]
pub struct AdminRequest {
    /// The admin key for authentication
    pub key: String,
    /// Command to execute (status, scan, pause, config-update)
    pub command: String,
    /// Optional command-specific arguments
    #[serde(default)]
    pub args: serde_json::Value,
}

/// JSON response returned over the admin socket.
#[derive(Debug, Serialize)]
pub struct AdminResponse {
    /// Whether the command succeeded
    pub ok: bool,
    /// Human-readable status message
    pub message: String,
    /// Optional structured data (e.g., status details)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

#[derive(Debug)]
#[allow(dead_code)]
struct RateLimiter {
    failures: HashMap<String, (u32, Instant)>,
    global_failures: u32,
    global_lockout_until: Option<Instant>,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            failures: HashMap::new(),
            global_failures: 0,
            global_lockout_until: None,
        }
    }

    fn is_locked_out(&self) -> bool {
        if let Some(until) = self.global_lockout_until {
            Instant::now() < until
        } else {
            false
        }
    }

    fn record_failure(&mut self) -> bool {
        self.global_failures += 1;
        if self.global_failures >= MAX_FAILURES {
            self.global_lockout_until = Some(Instant::now() + LOCKOUT_DURATION);
            true // locked out
        } else {
            false
        }
    }

    fn reset(&mut self) {
        self.global_failures = 0;
        self.global_lockout_until = None;
    }
}

/// Listens on a Unix domain socket for authenticated admin commands.
///
/// Each connection reads newline-delimited JSON requests, verifies the admin key
/// against the stored Argon2 hash, and dispatches commands. Rate limiting prevents
/// brute-force key guessing.
pub struct AdminSocket {
    socket_path: PathBuf,
    key_hash_path: PathBuf,
    alert_tx: mpsc::Sender<Alert>,
    rate_limiter: Arc<Mutex<RateLimiter>>,
    paused_until: Arc<Mutex<Option<Instant>>>,
}

/// Generate a new admin key: returns (display_key, argon2_hash)
pub fn generate_admin_key() -> Result<(String, String)> {
    use rand::RngCore;
    let mut key_bytes = [0u8; KEY_BYTES];
    OsRng.fill_bytes(&mut key_bytes);

    let key_hex = hex::encode(key_bytes);
    let display_key = format!("{}{}", KEY_PREFIX, key_hex);

    let hash = hash_key(&display_key)?;
    Ok((display_key, hash))
}

/// Hash a key with Argon2
pub fn hash_key(key: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(key.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("Failed to hash key: {}", e))?;
    Ok(hash.to_string())
}

/// Verify a key against an Argon2 hash
pub fn verify_key(key: &str, hash: &str) -> bool {
    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(key.as_bytes(), &parsed)
        .is_ok()
}

/// Check admin key state on startup. Does NOT generate a key — that only
/// happens during `clawtower harden` via `generate_and_show_admin_key()`.
/// If no hash file exists, logs a hint and returns Ok. The admin socket will
/// reject all commands until a key is generated.
pub fn init_admin_key(hash_path: &Path) -> Result<()> {
    if hash_path.exists() {
        return Ok(());
    }

    eprintln!("Admin key not yet generated — run 'clawtower harden' to generate");
    Ok(())
}

/// Generate a new admin key, display it once, write the Argon2 hash, and
/// set chattr +i. Called by `clawtower generate-key` (which `install.sh`
/// invokes during the harden step). Idempotent: skips if hash already exists.
/// Returns true if a new key was generated, false if one already existed.
pub fn generate_and_show_admin_key(hash_path: &Path) -> Result<bool> {
    if hash_path.exists() {
        eprintln!("Admin key already exists at {} — skipping generation", hash_path.display());
        return Ok(false);
    }

    let (display_key, hash) = generate_admin_key()?;

    if let Some(parent) = hash_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(hash_path, &hash)
        .with_context(|| format!("Failed to write key hash to {}", hash_path.display()))?;

    // Make the hash file immutable to prevent tampering.
    // Try direct chattr first, fall back to systemd-run (for dropped CAP_LINUX_IMMUTABLE).
    let path_str = hash_path.to_string_lossy();
    if !std::process::Command::new("chattr")
        .args(["+i", &*path_str])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        let _ = std::process::Command::new("systemd-run")
            .args(["--wait", "--collect", "--quiet", "chattr", "+i", &*path_str])
            .status();
    }

    // Key is always 69 chars: "OCAV-" (5) + 64 hex digits
    const W: usize = 73; // inner width: 2-pad + 69-key + 2-pad
    let bar: String = "═".repeat(W);
    let pad: String = " ".repeat(W);
    let title = "ADMIN KEY GENERATED -- SAVE THIS NOW, IT WILL NOT BE SHOWN AGAIN:";
    let hint  = "Store in your password manager or write it down.";

    eprintln!();
    eprintln!("╔{bar}╗");
    eprintln!("║  {title:<w$}║", w = W - 2);
    eprintln!("║{pad}║");
    eprintln!("║  {display_key}  ║");
    eprintln!("║{pad}║");
    eprintln!("║  {hint:<w$}║", w = W - 2);
    eprintln!("╚{bar}╝");
    eprintln!();

    // Force the user to confirm they saved the key before continuing.
    // This is a one-way door — the key is never stored and cannot be recovered.
    use std::io::{BufRead, Write};
    let stdin = std::io::stdin();
    let mut stderr = std::io::stderr();
    loop {
        let _ = write!(stderr, "Type exactly \"I SAVED MY KEY\" to continue: ");
        let _ = stderr.flush();
        let mut line = String::new();
        if stdin.lock().read_line(&mut line).is_err() {
            break; // broken pipe / EOF — let the caller handle it
        }
        if line.trim() == "I SAVED MY KEY" {
            break;
        }
        eprintln!("  ↳ Please type exactly: I SAVED MY KEY");
    }
    eprintln!();

    Ok(true)
}

impl AdminSocket {
    /// Create a new admin socket handler with the given paths and alert channel.
    pub fn new(
        socket_path: PathBuf,
        key_hash_path: PathBuf,
        alert_tx: mpsc::Sender<Alert>,
    ) -> Self {
        Self {
            socket_path,
            key_hash_path,
            alert_tx,
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new())),
            paused_until: Arc::new(Mutex::new(None)),
        }
    }

    /// Check if monitoring is currently paused
    #[allow(dead_code)]
    pub fn paused_until(&self) -> Arc<Mutex<Option<Instant>>> {
        self.paused_until.clone()
    }

    /// Start listening for connections on the Unix socket. Runs until the process exits.
    pub async fn run(&self) -> Result<()> {
        // Remove stale socket
        let _ = std::fs::remove_file(&self.socket_path);

        let listener = UnixListener::bind(&self.socket_path)
            .with_context(|| format!("Failed to bind admin socket at {}", self.socket_path.display()))?;

        // Set permissions: owner clawtower, group openclaw, mode 0660
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.socket_path, std::fs::Permissions::from_mode(0o660))?;
        }

        let _ = self.alert_tx.send(Alert::new(
            Severity::Info,
            "admin",
            &format!("Admin socket listening on {}", self.socket_path.display()),
        )).await;

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let key_hash_path = self.key_hash_path.clone();
                    let alert_tx = self.alert_tx.clone();
                    let rate_limiter = self.rate_limiter.clone();
                    let paused_until = self.paused_until.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(
                            stream,
                            &key_hash_path,
                            alert_tx,
                            rate_limiter,
                            paused_until,
                        )
                        .await
                        {
                            eprintln!("Admin connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Admin socket accept error: {}", e);
                }
            }
        }
    }
}

async fn handle_connection(
    stream: tokio::net::UnixStream,
    key_hash_path: &Path,
    alert_tx: mpsc::Sender<Alert>,
    rate_limiter: Arc<Mutex<RateLimiter>>,
    paused_until: Arc<Mutex<Option<Instant>>>,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let response = process_request(
            &line,
            key_hash_path,
            &alert_tx,
            &rate_limiter,
            &paused_until,
        )
        .await;

        let json = serde_json::to_string(&response)?;
        writer.write_all(json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
    }

    Ok(())
}

async fn process_request(
    line: &str,
    key_hash_path: &Path,
    alert_tx: &mpsc::Sender<Alert>,
    rate_limiter: &Arc<Mutex<RateLimiter>>,
    paused_until: &Arc<Mutex<Option<Instant>>>,
) -> AdminResponse {
    // Parse request
    let req: AdminRequest = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => {
            return AdminResponse {
                ok: false,
                message: format!("Invalid JSON: {}", e),
                data: None,
            }
        }
    };

    // Check lockout
    {
        let rl = rate_limiter.lock().await;
        if rl.is_locked_out() {
            return AdminResponse {
                ok: false,
                message: "Locked out due to repeated auth failures. Try again later.".into(),
                data: None,
            };
        }
    }

    // Load and verify key
    let key_hash = match std::fs::read_to_string(key_hash_path) {
        Ok(h) => h.trim().to_string(),
        Err(_) => {
            return AdminResponse {
                ok: false,
                message: "Admin key not initialized".into(),
                data: None,
            }
        }
    };

    if !verify_key(&req.key, &key_hash) {
        let locked_out = {
            let mut rl = rate_limiter.lock().await;
            rl.record_failure()
        };

        let msg = if locked_out {
            "Authentication FAILED — account LOCKED OUT for 1 hour"
        } else {
            "Authentication failed"
        };

        let _ = alert_tx
            .send(Alert::new(Severity::Critical, "admin", &format!(
                "🚨 Admin auth failure (command: {}). {}",
                req.command, msg
            )))
            .await;

        return AdminResponse {
            ok: false,
            message: msg.into(),
            data: None,
        };
    }

    // Auth success — reset rate limiter
    {
        let mut rl = rate_limiter.lock().await;
        rl.reset();
    }

    let _ = alert_tx
        .send(Alert::new(
            Severity::Info,
            "admin",
            &format!("Admin command authenticated: {}", req.command),
        ))
        .await;

    // Dispatch command
    match req.command.as_str() {
        "status" => {
            let paused = {
                let p = paused_until.lock().await;
                match *p {
                    Some(until) if Instant::now() < until => {
                        Some(until.duration_since(Instant::now()).as_secs())
                    }
                    _ => None,
                }
            };
            AdminResponse {
                ok: true,
                message: "ClawTower running".into(),
                data: Some(serde_json::json!({
                    "status": "running",
                    "paused_seconds_remaining": paused,
                })),
            }
        }
        "scan" => {
            // Trigger on-demand scan (placeholder — actual scan integration TBD)
            let _ = alert_tx
                .send(Alert::new(Severity::Info, "admin", "Manual scan triggered via admin socket"))
                .await;
            AdminResponse {
                ok: true,
                message: "Scan triggered".into(),
                data: None,
            }
        }
        "pause" => {
            let minutes = req.args.get("minutes")
                .and_then(|v| v.as_u64())
                .unwrap_or(5)
                .min(MAX_PAUSE_MINUTES);

            {
                let mut p = paused_until.lock().await;
                *p = Some(Instant::now() + Duration::from_secs(minutes * 60));
            }

            let _ = alert_tx
                .send(Alert::new(
                    Severity::Warning,
                    "admin",
                    &format!("Monitoring paused for {} minutes (auto-resume)", minutes),
                ))
                .await;

            AdminResponse {
                ok: true,
                message: format!("Paused for {} minutes", minutes),
                data: None,
            }
        }
        "config-update" => {
            // Placeholder for config updates — would need specific field handling
            let _ = alert_tx
                .send(Alert::new(Severity::Info, "admin", "Config update requested via admin socket"))
                .await;
            AdminResponse {
                ok: true,
                message: "Config update acknowledged (not yet implemented)".into(),
                data: None,
            }
        }
        "incident-mode" => {
            let action = req.args.get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("status");

            const INCIDENT_FILE: &str = "/var/run/clawtower/incident-mode.active";
            const LOCK_FILE: &str = "/var/run/clawtower/clawsudo.locked";

            match action {
                "activate" => {
                    let _ = std::fs::create_dir_all("/var/run/clawtower");
                    let _ = std::fs::write(INCIDENT_FILE, "activated via admin socket\n");

                    let lock_clawsudo = req.args.get("lock_clawsudo")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true);
                    if lock_clawsudo {
                        let _ = std::fs::write(LOCK_FILE, "locked by incident mode\n");
                    }

                    let _ = alert_tx
                        .send(Alert::new(
                            Severity::Critical,
                            "admin",
                            "INCIDENT MODE ACTIVATED — aggregation tightened, clawsudo locked",
                        ))
                        .await;

                    AdminResponse {
                        ok: true,
                        message: "Incident mode activated".into(),
                        data: Some(serde_json::json!({
                            "clawsudo_locked": lock_clawsudo,
                        })),
                    }
                }
                "deactivate" => {
                    let _ = std::fs::remove_file(INCIDENT_FILE);
                    let _ = std::fs::remove_file(LOCK_FILE);

                    let _ = alert_tx
                        .send(Alert::new(
                            Severity::Warning,
                            "admin",
                            "Incident mode deactivated — returning to normal aggregation",
                        ))
                        .await;

                    AdminResponse {
                        ok: true,
                        message: "Incident mode deactivated".into(),
                        data: None,
                    }
                }
                _ => {
                    // status (default)
                    let active = Path::new(INCIDENT_FILE).exists();
                    let clawsudo_locked = Path::new(LOCK_FILE).exists();
                    AdminResponse {
                        ok: true,
                        message: if active { "Incident mode is ACTIVE".into() } else { "Incident mode is inactive".into() },
                        data: Some(serde_json::json!({
                            "active": active,
                            "clawsudo_locked": clawsudo_locked,
                        })),
                    }
                }
            }
        }
        other => AdminResponse {
            ok: false,
            message: format!("Unknown command: {}", other),
            data: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let (key, hash) = generate_admin_key().unwrap();
        assert!(key.starts_with("OCAV-"));
        assert_eq!(key.len(), 5 + 64); // "OCAV-" + 64 hex chars
        assert!(hash.starts_with("$argon2"));
    }

    #[test]
    fn test_key_verification_success() {
        let (key, hash) = generate_admin_key().unwrap();
        assert!(verify_key(&key, &hash));
    }

    #[test]
    fn test_key_verification_failure() {
        let (_key, hash) = generate_admin_key().unwrap();
        assert!(!verify_key("OCAV-wrong_key_here", &hash));
    }

    #[test]
    fn test_key_verification_bad_hash() {
        assert!(!verify_key("OCAV-test", "not_a_valid_hash"));
    }

    #[tokio::test]
    async fn test_rate_limiter_lockout() {
        let mut rl = RateLimiter::new();
        assert!(!rl.is_locked_out());

        // First two failures don't lock out
        assert!(!rl.record_failure());
        assert!(!rl.is_locked_out());
        assert!(!rl.record_failure());
        assert!(!rl.is_locked_out());

        // Third failure triggers lockout
        assert!(rl.record_failure());
        assert!(rl.is_locked_out());
    }

    #[tokio::test]
    async fn test_rate_limiter_reset() {
        let mut rl = RateLimiter::new();
        rl.record_failure();
        rl.record_failure();
        rl.record_failure();
        assert!(rl.is_locked_out());

        rl.reset();
        assert!(!rl.is_locked_out());
        assert_eq!(rl.global_failures, 0);
    }

    #[test]
    fn test_admin_request_parsing() {
        let json = r#"{"key": "OCAV-abc123", "command": "status", "args": {}}"#;
        let req: AdminRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.key, "OCAV-abc123");
        assert_eq!(req.command, "status");
    }

    // --- NEW REGRESSION TESTS ---

    #[test]
    fn test_key_prefix_format() {
        let (key, _) = generate_admin_key().unwrap();
        assert!(key.starts_with("OCAV-"), "Key must start with OCAV- prefix");
        // Hex chars only after prefix
        let hex_part = &key[5..];
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()),
            "Key suffix must be hex only, got: {}", hex_part);
    }

    #[test]
    fn test_key_uniqueness() {
        let (k1, _) = generate_admin_key().unwrap();
        let (k2, _) = generate_admin_key().unwrap();
        assert_ne!(k1, k2, "Two generated keys should not collide");
    }

    #[test]
    fn test_verify_empty_key() {
        let (_, hash) = generate_admin_key().unwrap();
        assert!(!verify_key("", &hash));
    }

    #[test]
    fn test_verify_empty_hash() {
        assert!(!verify_key("OCAV-test", ""));
    }

    #[test]
    fn test_verify_key_with_prefix_stripped() {
        // Ensure someone can't auth with just the hex part
        let (key, hash) = generate_admin_key().unwrap();
        let hex_only = &key[5..]; // strip "OCAV-"
        assert!(!verify_key(hex_only, &hash), "Hex-only key should not verify");
    }

    #[test]
    fn test_hash_key_produces_argon2_format() {
        let hash = hash_key("test-key").unwrap();
        assert!(hash.starts_with("$argon2"), "Hash should be argon2 format");
        assert!(hash.contains("$"), "Hash should contain $ separators");
    }

    #[test]
    fn test_hash_key_different_salts() {
        let h1 = hash_key("same-key").unwrap();
        let h2 = hash_key("same-key").unwrap();
        assert_ne!(h1, h2, "Same key hashed twice should produce different hashes (different salts)");
        // But both should verify
        assert!(verify_key("same-key", &h1));
        assert!(verify_key("same-key", &h2));
    }

    #[tokio::test]
    async fn test_rate_limiter_exact_threshold() {
        let mut rl = RateLimiter::new();
        // Exactly MAX_FAILURES-1 should not lock
        for _ in 0..MAX_FAILURES - 1 {
            assert!(!rl.record_failure());
        }
        assert!(!rl.is_locked_out());
        // The MAX_FAILURES-th failure triggers lockout
        assert!(rl.record_failure());
        assert!(rl.is_locked_out());
    }

    #[tokio::test]
    async fn test_rate_limiter_reset_then_re_lockout() {
        let mut rl = RateLimiter::new();
        for _ in 0..MAX_FAILURES { rl.record_failure(); }
        assert!(rl.is_locked_out());
        rl.reset();
        assert!(!rl.is_locked_out());
        // Can lock out again
        for _ in 0..MAX_FAILURES { rl.record_failure(); }
        assert!(rl.is_locked_out());
    }

    #[test]
    fn test_admin_request_malformed_json() {
        let result: Result<AdminRequest, _> = serde_json::from_str("not json at all");
        assert!(result.is_err());
    }

    #[test]
    fn test_admin_request_missing_key() {
        let json = r#"{"command": "status"}"#;
        let result: Result<AdminRequest, _> = serde_json::from_str(json);
        assert!(result.is_err(), "Missing required 'key' field should error");
    }

    #[test]
    fn test_admin_request_missing_command() {
        let json = r#"{"key": "OCAV-abc"}"#;
        let result: Result<AdminRequest, _> = serde_json::from_str(json);
        assert!(result.is_err(), "Missing required 'command' field should error");
    }

    #[test]
    fn test_admin_response_serialization() {
        let resp = AdminResponse {
            ok: true,
            message: "test".to_string(),
            data: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("data"), "None data should be skipped");

        let resp2 = AdminResponse {
            ok: false,
            message: "err".to_string(),
            data: Some(serde_json::json!({"foo": "bar"})),
        };
        let json2 = serde_json::to_string(&resp2).unwrap();
        assert!(json2.contains("data"));
    }

    #[test]
    fn test_init_admin_key_existing_hash() {
        let dir = tempfile::tempdir().unwrap();
        let hash_path = dir.path().join("admin.hash");
        std::fs::write(&hash_path, "existing-hash").unwrap();
        // Should return Ok without overwriting
        init_admin_key(&hash_path).unwrap();
        let content = std::fs::read_to_string(&hash_path).unwrap();
        assert_eq!(content, "existing-hash", "Existing hash should not be overwritten");
    }

    #[test]
    fn test_init_admin_key_no_hash_does_not_generate() {
        let dir = tempfile::tempdir().unwrap();
        let hash_path = dir.path().join("admin.hash");
        // init should return Ok but NOT create the file
        init_admin_key(&hash_path).unwrap();
        assert!(!hash_path.exists(), "init_admin_key should not generate a key");
    }

    #[test]
    fn test_generate_and_show_skips_existing() {
        let dir = tempfile::tempdir().unwrap();
        let hash_path = dir.path().join("admin.hash");
        std::fs::write(&hash_path, "existing-hash").unwrap();
        let generated = generate_and_show_admin_key(&hash_path).unwrap();
        assert!(!generated, "Should skip when hash already exists");
        let content = std::fs::read_to_string(&hash_path).unwrap();
        assert_eq!(content, "existing-hash", "Existing hash should not be overwritten");
    }

    #[test]
    fn test_generate_and_show_creates_key() {
        let dir = tempfile::tempdir().unwrap();
        let hash_path = dir.path().join("admin.hash");
        let generated = generate_and_show_admin_key(&hash_path).unwrap();
        assert!(generated, "Should generate a new key");
        assert!(hash_path.exists(), "Hash file should be created");
        let content = std::fs::read_to_string(&hash_path).unwrap();
        assert!(content.starts_with("$argon2"), "Hash should be argon2 format");
    }

    #[test]
    fn test_admin_request_no_args() {
        let json = r#"{"key": "OCAV-abc123", "command": "scan"}"#;
        let req: AdminRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.command, "scan");
        assert!(req.args.is_null());
    }

    #[test]
    fn test_incident_mode_request_parsing() {
        let json = r#"{"key": "OCAV-abc", "command": "incident-mode", "args": {"action": "activate", "lock_clawsudo": true}}"#;
        let req: AdminRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.command, "incident-mode");
        assert_eq!(req.args["action"], "activate");
        assert_eq!(req.args["lock_clawsudo"], true);
    }

    #[test]
    fn test_incident_mode_status_request() {
        let json = r#"{"key": "OCAV-abc", "command": "incident-mode", "args": {"action": "status"}}"#;
        let req: AdminRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.command, "incident-mode");
        assert_eq!(req.args["action"], "status");
    }
}
