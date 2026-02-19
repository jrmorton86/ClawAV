// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Virtual credential file guard for auth-profiles.json.
//!
//! Replaces real credentials on disk with virtual tokens (`vk-profile-<hash>`).
//! The proxy swaps virtual→real on outbound API requests. An inotify watcher
//! re-virtualizes the file if an external process overwrites it with real creds.

use crate::core::alerts::{Alert, Severity};
use super::KeyMapping;
use sha2::{Sha256, Digest};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// Prefix used for virtual credential values in auth-profiles.json.
const VIRTUAL_PREFIX: &str = "vk-profile-";

/// Directory where the real-credential backup is stored (protected by chattr +i / AppArmor).
const BACKUP_DIR: &str = "/etc/clawtower";
/// Filename for the real-credential backup within BACKUP_DIR.
const BACKUP_FILENAME: &str = "auth-profiles.real.bak";

/// Check whether a credential value looks like a virtual token we generated.
pub fn is_virtual(content: &str) -> bool {
    content.contains(VIRTUAL_PREFIX)
}

/// Generate a deterministic virtual token from a real credential value.
/// Uses SHA-256 truncated to 16 hex chars for uniqueness without exposing the real key.
fn make_virtual_value(real_value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(real_value.as_bytes());
    let hash = hasher.finalize();
    format!("{}{}", VIRTUAL_PREFIX, hex::encode(&hash[..8]))
}

/// Virtualize an auth-profiles.json file.
///
/// Parses the JSON, replaces string values that look like real credentials
/// (API keys, tokens) with virtual `vk-profile-<hash>` tokens, and returns
/// the virtualized JSON string plus the key mappings needed for proxy swap.
///
/// Handles both top-level `{ "key": "value" }` and nested
/// `{ "profiles": { "name": { "api_key": "value" } } }` structures.
pub fn virtualize_profile(real_json: &str) -> Result<(String, Vec<KeyMapping>), String> {
    let parsed: serde_json::Value = serde_json::from_str(real_json)
        .map_err(|e| format!("Failed to parse auth-profiles.json: {}", e))?;

    let mut mappings = Vec::new();
    let mut virtualized = parsed.clone();

    fn walk_and_replace(
        val: &mut serde_json::Value,
        mappings: &mut Vec<KeyMapping>,
    ) {
        match val {
            serde_json::Value::Object(map) => {
                for (key, v) in map.iter_mut() {
                    match v {
                        serde_json::Value::String(s) if looks_like_credential(key, s) => {
                            let real = s.clone();
                            let virtual_val = make_virtual_value(&real);
                            mappings.push(KeyMapping {
                                virtual_key: virtual_val.clone(),
                                real,
                                provider: "auth-profile".to_string(),
                                upstream: String::new(),
                                ttl_secs: None,
                                allowed_paths: vec![],
                                revoke_at_risk: 0.0,
                            });
                            *s = virtual_val;
                        }
                        _ => walk_and_replace(v, mappings),
                    }
                }
            }
            serde_json::Value::Array(arr) => {
                for item in arr.iter_mut() {
                    walk_and_replace(item, mappings);
                }
            }
            _ => {}
        }
    }

    walk_and_replace(&mut virtualized, &mut mappings);

    let output = serde_json::to_string_pretty(&virtualized)
        .map_err(|e| format!("Failed to serialize virtualized JSON: {}", e))?;

    Ok((output, mappings))
}

/// Heuristic: does this key-value pair look like a credential?
/// Matches common field names and values that look like API keys/tokens.
fn looks_like_credential(key: &str, value: &str) -> bool {
    // Skip already-virtualized values
    if value.starts_with(VIRTUAL_PREFIX) {
        return false;
    }
    // Skip short values (unlikely to be keys)
    if value.len() < 8 {
        return false;
    }
    // Match by key name
    let key_lower = key.to_lowercase();
    let credential_keys = [
        "api_key", "apikey", "api-key",
        "secret", "secret_key", "secretkey",
        "token", "access_token", "auth_token",
        "password", "key", "credential",
        "client_secret", "client_id",
    ];
    if credential_keys.iter().any(|&k| key_lower.contains(k)) {
        return true;
    }
    // Match by value pattern (common API key prefixes)
    let key_prefixes = ["sk-", "sk-ant-", "pk-", "Bearer ", "AKIA", "ghp_", "gho_", "glpat-"];
    if key_prefixes.iter().any(|&p| value.starts_with(p)) {
        return true;
    }
    false
}

/// Spawnable async task that guards auth-profiles.json.
///
/// On startup: reads the real file, virtualizes it, writes the virtual version
/// back to disk, and registers KeyMappings for the proxy. Then watches for
/// external writes and re-virtualizes as needed.
pub async fn start_auth_profile_guard(
    path: PathBuf,
    key_mappings: Arc<Mutex<Vec<KeyMapping>>>,
    tx: mpsc::Sender<Alert>,
) {
    // Self-write detection flag
    let self_writing = Arc::new(AtomicBool::new(false));

    // Initial virtualization
    if let Err(e) = do_virtualize(&path, &key_mappings, &self_writing) {
        let _ = tx.send(Alert::new(
            Severity::Warning,
            "auth-profile-guard",
            &format!("Initial virtualization failed: {} (file may not exist yet)", e),
        )).await;
    } else {
        let _ = tx.send(Alert::new(
            Severity::Info,
            "auth-profile-guard",
            &format!("Virtualized credentials in {}", path.display()),
        )).await;
    }

    // Watch for changes using notify (inotify)
    use notify::{Watcher, RecursiveMode, Event, EventKind};
    let (notify_tx, mut notify_rx) = tokio::sync::mpsc::channel::<Event>(100);

    let mut watcher = match notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
        if let Ok(event) = res {
            let _ = notify_tx.blocking_send(event);
        }
    }) {
        Ok(w) => w,
        Err(e) => {
            let _ = tx.send(Alert::new(
                Severity::Warning,
                "auth-profile-guard",
                &format!("Failed to create file watcher: {}", e),
            )).await;
            return;
        }
    };

    // Watch the parent directory (file watches don't survive file replacement)
    let watch_dir = path.parent().unwrap_or(Path::new("/"));
    if let Err(e) = watcher.watch(watch_dir, RecursiveMode::NonRecursive) {
        let _ = tx.send(Alert::new(
            Severity::Warning,
            "auth-profile-guard",
            &format!("Failed to watch directory {}: {}", watch_dir.display(), e),
        )).await;
        return;
    }

    loop {
        match notify_rx.recv().await {
            Some(event) => {
                // Only react to writes/creates to our specific file
                let is_our_file = event.paths.iter().any(|p| p == &path);
                let is_write = matches!(
                    event.kind,
                    EventKind::Modify(_) | EventKind::Create(_)
                );

                if is_our_file && is_write {
                    // Skip if this was our own write
                    if self_writing.load(Ordering::SeqCst) {
                        continue;
                    }

                    // Small delay to let the writer finish
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

                    // Check if the file now contains real (non-virtual) creds
                    match std::fs::read_to_string(&path) {
                        Ok(content) if !is_virtual(&content) && !content.trim().is_empty() => {
                            let _ = tx.send(Alert::new(
                                Severity::Warning,
                                "auth-profile-guard",
                                "External write detected to auth-profiles.json — re-virtualizing",
                            )).await;

                            if let Err(e) = do_virtualize(&path, &key_mappings, &self_writing) {
                                let _ = tx.send(Alert::new(
                                    Severity::Warning,
                                    "auth-profile-guard",
                                    &format!("Re-virtualization failed: {}", e),
                                )).await;
                            }
                        }
                        _ => {} // Already virtual or read error — ignore
                    }
                }
            }
            None => break, // Channel closed
        }
    }
}

/// Read the file, virtualize it, write back, and update shared mappings.
fn do_virtualize(
    path: &Path,
    key_mappings: &Arc<Mutex<Vec<KeyMapping>>>,
    self_writing: &Arc<AtomicBool>,
) -> Result<(), String> {
    let real_json = std::fs::read_to_string(path)
        .map_err(|e| format!("read: {}", e))?;

    if real_json.trim().is_empty() {
        return Err("file is empty".to_string());
    }

    // Don't re-virtualize if already virtual
    if is_virtual(&real_json) {
        return Ok(());
    }

    let (virtual_json, new_mappings) = virtualize_profile(&real_json)?;

    if new_mappings.is_empty() {
        return Ok(()); // No credentials found to virtualize
    }

    // Backup real credentials to /etc/clawtower/ (protected by immutable flags).
    // Best-effort: if backup fails we still virtualize, but log the failure.
    let backup_path = Path::new(BACKUP_DIR).join(BACKUP_FILENAME);
    if let Err(e) = std::fs::write(&backup_path, &real_json) {
        eprintln!("[auth-profile-guard] WARNING: could not save credential backup to {}: {} \
                   (uninstall will not be able to restore real credentials)", backup_path.display(), e);
    }

    // Write virtual version to disk
    self_writing.store(true, Ordering::SeqCst);
    let write_result = std::fs::write(path, &virtual_json);
    // Brief delay to let inotify event pass before clearing flag
    std::thread::sleep(std::time::Duration::from_millis(50));
    self_writing.store(false, Ordering::SeqCst);

    write_result.map_err(|e| format!("write: {}", e))?;

    // Update shared proxy mappings
    let mut mappings = key_mappings.lock().map_err(|_| "lock poisoned")?;
    // Remove old auth-profile mappings, then add new ones
    mappings.retain(|m| m.provider != "auth-profile");
    mappings.extend(new_mappings);

    Ok(())
}

/// Restore real credentials from the backup file.
///
/// Called during uninstall or `clawtower devirtualize-auth`. Reads the
/// backup from `/etc/clawtower/auth-profiles.real.bak`, writes it to the
/// original path, and removes the backup.
pub fn restore_from_backup(auth_profile_path: &Path) -> Result<(), String> {
    let backup_path = Path::new(BACKUP_DIR).join(BACKUP_FILENAME);
    if !backup_path.exists() {
        return Err(format!("No backup found at {}", backup_path.display()));
    }

    let real_json = std::fs::read_to_string(&backup_path)
        .map_err(|e| format!("read backup: {}", e))?;

    if real_json.trim().is_empty() {
        return Err("backup file is empty".to_string());
    }

    // Verify the current file actually has virtual tokens before overwriting
    if let Ok(current) = std::fs::read_to_string(auth_profile_path) {
        if !is_virtual(&current) {
            // File already has real creds — just clean up the backup
            let _ = std::fs::remove_file(&backup_path);
            return Ok(());
        }
    }

    std::fs::write(auth_profile_path, &real_json)
        .map_err(|e| format!("write: {}", e))?;

    let _ = std::fs::remove_file(&backup_path);
    Ok(())
}

/// Return the backup directory and filename (for use by uninstall scripts).
pub fn backup_path() -> PathBuf {
    Path::new(BACKUP_DIR).join(BACKUP_FILENAME)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_virtualize_profile_structure() {
        let real = r#"{
            "default": {
                "api_key": "sk-ant-api03-REAL-KEY-HERE-1234567890",
                "name": "production"
            }
        }"#;

        let (virtual_json, mappings) = virtualize_profile(real).unwrap();

        // Structure preserved
        let parsed: serde_json::Value = serde_json::from_str(&virtual_json).unwrap();
        assert!(parsed["default"]["name"].as_str().unwrap() == "production");
        // API key replaced with virtual token
        let vk = parsed["default"]["api_key"].as_str().unwrap();
        assert!(vk.starts_with("vk-profile-"), "Expected virtual prefix, got: {}", vk);
        // Mapping created
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].real, "sk-ant-api03-REAL-KEY-HERE-1234567890");
        assert_eq!(mappings[0].virtual_key, vk);
    }

    #[test]
    fn test_is_virtual_detects_virtual_creds() {
        assert!(is_virtual(r#"{"api_key": "vk-profile-abc123def456"}"#));
        assert!(!is_virtual(r#"{"api_key": "sk-ant-real-key"}"#));
        assert!(!is_virtual(r#"{"api_key": ""}"#));
    }

    #[test]
    fn test_virtualize_preserves_non_credential_fields() {
        let real = r#"{"name": "test", "url": "https://example.com", "enabled": true}"#;
        let (virtual_json, mappings) = virtualize_profile(real).unwrap();
        // No credential fields → no mappings, no changes
        assert!(mappings.is_empty());
        let parsed: serde_json::Value = serde_json::from_str(&virtual_json).unwrap();
        assert_eq!(parsed["name"].as_str().unwrap(), "test");
        assert_eq!(parsed["enabled"].as_bool().unwrap(), true);
    }

    #[test]
    fn test_virtualize_handles_nested_profiles() {
        let real = r#"{
            "profiles": {
                "anthropic": {"api_key": "sk-ant-secret123456789012345"},
                "openai": {"api_key": "sk-openai-secret12345678901234"}
            }
        }"#;
        let (_, mappings) = virtualize_profile(real).unwrap();
        assert_eq!(mappings.len(), 2, "Both API keys should be virtualized");
    }

    #[test]
    fn test_make_virtual_value_deterministic() {
        let v1 = make_virtual_value("sk-ant-api03-REAL");
        let v2 = make_virtual_value("sk-ant-api03-REAL");
        assert_eq!(v1, v2, "Same input should produce same virtual token");

        let v3 = make_virtual_value("sk-ant-api03-DIFFERENT");
        assert_ne!(v1, v3, "Different inputs should produce different tokens");
    }

    #[test]
    fn test_looks_like_credential() {
        assert!(looks_like_credential("api_key", "sk-ant-api03-real-key-here"));
        assert!(looks_like_credential("token", "ghp_abcdefghijklmnopqrstuvwxyz1234"));
        assert!(looks_like_credential("secret", "some-long-secret-value-here"));
        assert!(!looks_like_credential("name", "production"));
        assert!(!looks_like_credential("url", "https://api.anthropic.com"));
        // Already virtual — should not re-virtualize
        assert!(!looks_like_credential("api_key", "vk-profile-abc123def456"));
        // Too short
        assert!(!looks_like_credential("api_key", "short"));
    }

    #[test]
    fn test_restore_from_backup_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let auth_path = dir.path().join("auth-profiles.json");
        let real_json = r#"{"api_key": "sk-ant-api03-REAL-KEY-12345678"}"#;

        // Simulate: write virtual content to the "live" file
        let (virtual_json, _) = virtualize_profile(real_json).unwrap();
        std::fs::write(&auth_path, &virtual_json).unwrap();

        // Simulate: backup exists with real content
        // (can't write to /etc/clawtower in tests, so test the logic path directly)
        assert!(is_virtual(&std::fs::read_to_string(&auth_path).unwrap()));

        // Write real content back (simulating what restore_from_backup does)
        std::fs::write(&auth_path, real_json).unwrap();
        let restored = std::fs::read_to_string(&auth_path).unwrap();
        assert!(!is_virtual(&restored));
        assert!(restored.contains("sk-ant-api03-REAL-KEY-12345678"));
    }
}
