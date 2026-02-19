// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Auto-remediation of hardcoded API keys found in OpenClaw config files.
//!
//! Replaces real API keys with proxy virtual keys and records each remediation
//! in a JSON manifest. Encrypted copies of the original keys are stored so they
//! can be restored by an administrator.
//!
//! Components:
//! - **Manifest**: JSON file tracking every key that was remediated
//! - **Encryption**: AES-256-GCM encryption of original keys using machine-id
//! - **Provider detection**: Identify API provider from JSON path or key prefix
//! - **Key extraction**: Find hardcoded keys in JSON and YAML config files
//! - **Rewriting**: Replace keys in-place in JSON/YAML files
//! - **Proxy overlay**: Generate TOML overlay with virtual-to-real key mappings

use serde::{Deserialize, Serialize};

// ── Constants ───────────────────────────────────────────────────────────────

/// Path to the JSON manifest tracking all remediated keys.
pub const MANIFEST_PATH: &str = "/etc/clawtower/remediated-keys.json";

/// Path to the TOML overlay file that configures proxy key mappings.
pub const OVERLAY_PATH: &str = "/etc/clawtower/config.d/90-remediated-keys.toml";

/// Key prefixes that indicate hardcoded API keys (same as scanner).
const KEY_PREFIXES: &[&str] = &[
    "sk-ant-",  // Anthropic
    "sk-proj-", // OpenAI project keys
    "sk-",      // OpenAI legacy
    "key-",     // Generic API keys
    "gsk_",     // Groq
    "xai-",     // xAI/Grok
    "AKIA",     // AWS access key ID
    "ghp_",     // GitHub personal access token
    "glpat-",   // GitLab personal access token
    "xoxb-",    // Slack bot token
    "xoxp-",    // Slack user token
];

// ── Manifest types ──────────────────────────────────────────────────────────

/// Top-level manifest tracking all remediated keys.
#[derive(Debug, Serialize, Deserialize)]
pub struct RemediationManifest {
    /// Schema version (currently 1).
    pub version: u32,
    /// List of individual key remediations.
    pub remediations: Vec<RemediationEntry>,
}

/// A single remediated key entry.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RemediationEntry {
    /// Unique identifier for this remediation (UUID).
    pub id: String,
    /// ISO 8601 timestamp of when the remediation occurred.
    pub timestamp: String,
    /// Path to the source file that contained the key.
    pub source_file: String,
    /// Dot-separated JSON/YAML path to the key within the file.
    pub json_path: String,
    /// First few characters of the original key (for identification).
    pub original_key_prefix: String,
    /// SHA-256 hash of the full original key.
    pub original_key_hash: String,
    /// AES-256-GCM encrypted copy of the original key (base64).
    pub encrypted_real_key: String,
    /// Hex-encoded salt used for encryption key derivation.
    pub encryption_salt: String,
    /// Virtual key that replaced the original.
    pub virtual_key: String,
    /// Detected provider name (e.g., "anthropic", "openai").
    pub provider: String,
    /// Upstream API URL for the provider.
    pub upstream: String,
}

/// Load the remediation manifest from disk, returning an empty manifest if
/// the file does not exist or cannot be parsed.
pub fn load_manifest(path: &str) -> RemediationManifest {
    match std::fs::read_to_string(path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or(RemediationManifest {
            version: 1,
            remediations: Vec::new(),
        }),
        Err(_) => RemediationManifest {
            version: 1,
            remediations: Vec::new(),
        },
    }
}

/// Save the remediation manifest to disk as pretty-printed JSON.
pub fn save_manifest(path: &str, manifest: &RemediationManifest) -> Result<(), String> {
    let json = serde_json::to_string_pretty(manifest)
        .map_err(|e| format!("Failed to serialize manifest: {}", e))?;
    std::fs::write(path, json).map_err(|e| format!("Failed to write manifest to {}: {}", path, e))
}

// ── AES-256-GCM encryption ─────────────────────────────────────────────────

/// Result of encrypting a key: ciphertext (base64) and salt (hex).
pub struct EncryptedKey {
    /// Base64-encoded ciphertext (AES-256-GCM).
    pub ciphertext: String,
    /// Hex-encoded 16-byte random salt used for key derivation.
    pub salt: String,
}

/// Derive a 32-byte encryption key from `/etc/machine-id` + salt using SHA-256.
fn derive_encryption_key(salt: &[u8]) -> Result<[u8; 32], String> {
    use sha2::{Digest, Sha256};

    let machine_id = std::fs::read_to_string("/etc/machine-id")
        .map_err(|e| format!("Failed to read /etc/machine-id: {}", e))?;
    let machine_id = machine_id.trim();

    let mut hasher = Sha256::new();
    hasher.update(machine_id.as_bytes());
    hasher.update(salt);
    let result = hasher.finalize();

    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    Ok(key)
}

/// Encrypt a plaintext API key using AES-256-GCM.
///
/// Derives the encryption key from `/etc/machine-id` + a random 16-byte salt.
/// The first 12 bytes of the salt are used as the GCM nonce.
pub fn encrypt_key(plaintext: &str) -> Result<EncryptedKey, String> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use rand::RngCore;

    // Generate random 16-byte salt
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);

    let key_bytes = derive_encryption_key(&salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| format!("Failed to create cipher: {}", e))?;

    // Use first 12 bytes of salt as nonce
    let nonce = Nonce::from_slice(&salt[..12]);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    Ok(EncryptedKey {
        ciphertext: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &ciphertext,
        ),
        salt: hex::encode(salt),
    })
}

/// Decrypt an encrypted API key using AES-256-GCM.
///
/// Reconstructs the encryption key from `/etc/machine-id` + the stored salt.
pub fn decrypt_key(encrypted: &EncryptedKey) -> Result<String, String> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};

    let salt =
        hex::decode(&encrypted.salt).map_err(|e| format!("Failed to decode salt hex: {}", e))?;

    if salt.len() < 12 {
        return Err("Salt too short for nonce derivation".to_string());
    }

    let key_bytes = derive_encryption_key(&salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| format!("Failed to create cipher: {}", e))?;

    let nonce = Nonce::from_slice(&salt[..12]);

    let ciphertext = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &encrypted.ciphertext,
    )
    .map_err(|e| format!("Failed to decode ciphertext base64: {}", e))?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| format!("Decryption failed: {}", e))?;

    String::from_utf8(plaintext).map_err(|e| format!("Decrypted data is not valid UTF-8: {}", e))
}

// ── Provider detection ──────────────────────────────────────────────────────

/// Detect the API provider and upstream URL from a JSON path and/or key value.
///
/// Two-stage detection:
/// 1. JSON path patterns (e.g., `channels.slack.*` -> slack)
/// 2. Key prefix fallback (e.g., `sk-ant-` -> anthropic)
///
/// Returns `(provider, upstream_url)`. Unknown keys return `("unknown", "")`.
pub fn detect_provider_from_context(json_path: &str, key_value: &str) -> (String, String) {
    // Stage 1: JSON path patterns
    let path_lower = json_path.to_lowercase();

    if path_lower.contains("channels.slack") {
        return ("slack".to_string(), "https://slack.com/api".to_string());
    }
    if path_lower.contains("providers.anthropic") {
        return (
            "anthropic".to_string(),
            "https://api.anthropic.com".to_string(),
        );
    }
    if path_lower.contains("providers.openai") {
        return (
            "openai".to_string(),
            "https://api.openai.com".to_string(),
        );
    }
    if path_lower.contains("providers.groq") {
        return (
            "groq".to_string(),
            "https://api.groq.com/openai".to_string(),
        );
    }
    if path_lower.contains("providers.xai") {
        return ("xai".to_string(), "https://api.x.ai".to_string());
    }

    // Stage 2: Key prefix fallback (more specific before less specific)
    if key_value.starts_with("sk-ant-") {
        return (
            "anthropic".to_string(),
            "https://api.anthropic.com".to_string(),
        );
    }
    if key_value.starts_with("sk-proj-") {
        return (
            "openai".to_string(),
            "https://api.openai.com".to_string(),
        );
    }
    if key_value.starts_with("gsk_") {
        return (
            "groq".to_string(),
            "https://api.groq.com/openai".to_string(),
        );
    }
    if key_value.starts_with("xai-") {
        return ("xai".to_string(), "https://api.x.ai".to_string());
    }
    if key_value.starts_with("xoxb-") || key_value.starts_with("xoxp-") {
        return ("slack".to_string(), "https://slack.com/api".to_string());
    }
    if key_value.starts_with("ghp_") {
        return (
            "github".to_string(),
            "https://api.github.com".to_string(),
        );
    }
    if key_value.starts_with("glpat-") {
        return (
            "gitlab".to_string(),
            "https://gitlab.com/api/v4".to_string(),
        );
    }
    if key_value.starts_with("AKIA") {
        return (
            "aws".to_string(),
            "https://sts.amazonaws.com".to_string(),
        );
    }
    // Least specific: bare `sk-` -> openai (must come last)
    if key_value.starts_with("sk-") {
        return (
            "openai".to_string(),
            "https://api.openai.com".to_string(),
        );
    }

    ("unknown".to_string(), String::new())
}

// ── Key extraction ──────────────────────────────────────────────────────────

/// A key found during extraction from a config file.
pub struct FoundKey {
    /// Dot-separated path within the document (e.g., "providers.anthropic.api_key").
    pub json_path: String,
    /// The full key value.
    pub full_key: String,
    /// The matched prefix (e.g., "sk-ant-").
    pub prefix: String,
}

/// Check if a string value looks like a hardcoded API key.
///
/// Returns `Some((prefix, full_key))` if the value starts with a known prefix
/// and has at least 16 additional alphanumeric/hyphen/underscore characters.
fn match_key(value: &str) -> Option<(&'static str, String)> {
    // Check more specific prefixes first (order matters)
    for prefix in KEY_PREFIXES {
        if let Some(rest) = value.strip_prefix(prefix) {
            let key_chars: usize = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
                .count();
            if key_chars >= 16 {
                // Reconstruct the full key (prefix + valid key chars)
                let full_key: String =
                    format!("{}{}", prefix, &rest[..rest.chars().take(key_chars).map(|c| c.len_utf8()).sum::<usize>()]);
                return Some((prefix, full_key));
            }
        }
    }
    None
}

/// Extract hardcoded API keys from a JSON string.
///
/// Recursively walks the JSON tree and checks all string values against
/// known key prefixes. Returns keys with their dot-separated paths.
pub fn extract_keys_from_json(json_str: &str) -> Vec<FoundKey> {
    let value: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut found = Vec::new();
    walk_json_value(&value, String::new(), &mut found);
    found
}

/// Recursively walk a JSON value tree, collecting found keys.
fn walk_json_value(value: &serde_json::Value, path: String, found: &mut Vec<FoundKey>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                let child_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{}.{}", path, key)
                };
                walk_json_value(val, child_path, found);
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, val) in arr.iter().enumerate() {
                let child_path = format!("{}.{}", path, i);
                walk_json_value(val, child_path, found);
            }
        }
        serde_json::Value::String(s) => {
            if let Some((prefix, full_key)) = match_key(s) {
                found.push(FoundKey {
                    json_path: path,
                    full_key,
                    prefix: prefix.to_string(),
                });
            }
        }
        _ => {}
    }
}

/// Extract hardcoded API keys from a YAML string.
///
/// Recursively walks the YAML value tree and checks all string values
/// against known key prefixes. Returns keys with their dot-separated paths.
pub fn extract_keys_from_yaml(yaml_str: &str) -> Vec<FoundKey> {
    let value: serde_yaml::Value = match serde_yaml::from_str(yaml_str) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut found = Vec::new();
    walk_yaml_value(&value, String::new(), &mut found);
    found
}

/// Recursively walk a YAML value tree, collecting found keys.
fn walk_yaml_value(value: &serde_yaml::Value, path: String, found: &mut Vec<FoundKey>) {
    match value {
        serde_yaml::Value::Mapping(map) => {
            for (key, val) in map {
                let key_str = match key {
                    serde_yaml::Value::String(s) => s.clone(),
                    _ => format!("{:?}", key),
                };
                let child_path = if path.is_empty() {
                    key_str
                } else {
                    format!("{}.{}", path, key_str)
                };
                walk_yaml_value(val, child_path, found);
            }
        }
        serde_yaml::Value::Sequence(seq) => {
            for (i, val) in seq.iter().enumerate() {
                let child_path = format!("{}.{}", path, i);
                walk_yaml_value(val, child_path, found);
            }
        }
        serde_yaml::Value::String(s) => {
            if let Some((prefix, full_key)) = match_key(s) {
                found.push(FoundKey {
                    json_path: path,
                    full_key,
                    prefix: prefix.to_string(),
                });
            }
        }
        _ => {}
    }
}

// ── Config file rewriting ───────────────────────────────────────────────────

/// Rewrite a single key value in a JSON document.
///
/// Parses the JSON, walks to the specified dot-separated path, replaces the
/// value, and returns the pretty-printed result.
pub fn rewrite_json_key(
    json_str: &str,
    json_path: &str,
    new_value: &str,
) -> Result<String, String> {
    let mut root: serde_json::Value =
        serde_json::from_str(json_str).map_err(|e| format!("Invalid JSON: {}", e))?;

    let parts: Vec<&str> = json_path.split('.').collect();
    if parts.is_empty() {
        return Err("Empty JSON path".to_string());
    }

    // Navigate to the parent, then set the final key
    let mut current = &mut root;
    for (i, part) in parts.iter().enumerate() {
        if i == parts.len() - 1 {
            // Final key: replace the value
            match current {
                serde_json::Value::Object(map) => {
                    if map.contains_key(*part) {
                        map.insert(
                            part.to_string(),
                            serde_json::Value::String(new_value.to_string()),
                        );
                    } else {
                        return Err(format!("Key '{}' not found at path '{}'", part, json_path));
                    }
                }
                serde_json::Value::Array(arr) => {
                    let idx: usize = part
                        .parse()
                        .map_err(|_| format!("Invalid array index '{}' in path", part))?;
                    if idx < arr.len() {
                        arr[idx] = serde_json::Value::String(new_value.to_string());
                    } else {
                        return Err(format!(
                            "Array index {} out of bounds at path '{}'",
                            idx, json_path
                        ));
                    }
                }
                _ => {
                    return Err(format!(
                        "Cannot index into non-container at '{}'",
                        json_path
                    ));
                }
            }
        } else {
            // Intermediate key: navigate deeper
            current = match current {
                serde_json::Value::Object(map) => map.get_mut(*part).ok_or_else(|| {
                    format!("Key '{}' not found at path '{}'", part, json_path)
                })?,
                serde_json::Value::Array(arr) => {
                    let idx: usize = part
                        .parse()
                        .map_err(|_| format!("Invalid array index '{}' in path", part))?;
                    arr.get_mut(idx).ok_or_else(|| {
                        format!(
                            "Array index {} out of bounds at path '{}'",
                            idx, json_path
                        )
                    })?
                }
                _ => {
                    return Err(format!(
                        "Cannot navigate through non-container at '{}'",
                        json_path
                    ));
                }
            };
        }
    }

    serde_json::to_string_pretty(&root).map_err(|e| format!("Failed to serialize JSON: {}", e))
}

/// Rewrite a key value in a YAML document using line-based string replacement.
///
/// Preserves formatting by doing a simple find-and-replace of the old value
/// with the new value on each line.
pub fn rewrite_yaml_key(
    yaml_str: &str,
    old_value: &str,
    new_value: &str,
) -> Result<String, String> {
    if !yaml_str.contains(old_value) {
        return Err(format!("Value '{}' not found in YAML", old_value));
    }

    let result: String = yaml_str
        .lines()
        .map(|line| {
            if line.contains(old_value) {
                line.replace(old_value, new_value)
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    // Preserve trailing newline if original had one
    if yaml_str.ends_with('\n') && !result.ends_with('\n') {
        Ok(result + "\n")
    } else {
        Ok(result)
    }
}

// ── Proxy overlay writer ────────────────────────────────────────────────────

/// Write or append proxy key mappings to a TOML overlay file.
///
/// If the overlay file already exists, loads existing mappings, merges new
/// entries (deduplicating by virtual_key), and writes back. Creates a new
/// file if it does not exist.
pub fn write_proxy_overlay(
    path: &str,
    entries: &[RemediationEntry],
    real_keys: &[String],
) -> Result<(), String> {
    use crate::proxy::KeyMapping;

    // Load existing overlay if present
    let mut existing_mappings: Vec<KeyMapping> = Vec::new();

    if let Ok(content) = std::fs::read_to_string(path) {
        // Parse existing TOML to extract key_mapping entries
        if let Ok(parsed) = content.parse::<toml::Table>() {
            if let Some(proxy) = parsed.get("proxy") {
                if let Some(proxy_table) = proxy.as_table() {
                    if let Some(mappings) = proxy_table.get("key_mapping") {
                        if let Some(arr) = mappings.as_array() {
                            for item in arr {
                                if let Ok(mapping) =
                                    toml::from_str::<KeyMapping>(&toml::to_string(item).unwrap_or_default())
                                {
                                    existing_mappings.push(mapping);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Build new mappings from entries + real_keys
    for (entry, real_key) in entries.iter().zip(real_keys.iter()) {
        // Skip if virtual_key already exists in existing mappings
        if existing_mappings
            .iter()
            .any(|m| m.virtual_key == entry.virtual_key)
        {
            continue;
        }

        existing_mappings.push(KeyMapping {
            virtual_key: entry.virtual_key.clone(),
            real: real_key.clone(),
            provider: entry.provider.clone(),
            upstream: entry.upstream.clone(),
            ttl_secs: None,
            allowed_paths: Vec::new(),
            revoke_at_risk: 0.0,
        });
    }

    // Build TOML output
    #[derive(Serialize)]
    struct OverlayFile {
        proxy: ProxySection,
    }

    #[derive(Serialize)]
    struct ProxySection {
        key_mapping: Vec<KeyMapping>,
    }

    let overlay = OverlayFile {
        proxy: ProxySection {
            key_mapping: existing_mappings,
        },
    };

    let toml_str =
        toml::to_string_pretty(&overlay).map_err(|e| format!("Failed to serialize TOML: {}", e))?;

    std::fs::write(path, toml_str)
        .map_err(|e| format!("Failed to write overlay to {}: {}", path, e))
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Manifest tests ─────────────────────────────────────────────────

    #[test]
    fn test_manifest_roundtrip() {
        let manifest = RemediationManifest {
            version: 1,
            remediations: vec![RemediationEntry {
                id: "test-001".to_string(),
                timestamp: "2026-02-19T12:00:00Z".to_string(),
                source_file: "/home/openclaw/.openclaw/openclaw.json".to_string(),
                json_path: "providers.anthropic.api_key".to_string(),
                original_key_prefix: "sk-ant-".to_string(),
                original_key_hash: "abcdef1234567890".to_string(),
                encrypted_real_key: "base64ciphertext==".to_string(),
                encryption_salt: "aabbccdd00112233".to_string(),
                virtual_key: "vk-remediated-001".to_string(),
                provider: "anthropic".to_string(),
                upstream: "https://api.anthropic.com".to_string(),
            }],
        };

        let json = serde_json::to_string_pretty(&manifest).unwrap();
        let deserialized: RemediationManifest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.version, 1);
        assert_eq!(deserialized.remediations.len(), 1);
        assert_eq!(deserialized.remediations[0].id, "test-001");
        assert_eq!(deserialized.remediations[0].provider, "anthropic");
        assert_eq!(
            deserialized.remediations[0].virtual_key,
            "vk-remediated-001"
        );
    }

    #[test]
    fn test_load_manifest_missing_file() {
        let manifest = load_manifest("/nonexistent/path/remediated-keys.json");
        assert_eq!(manifest.version, 1);
        assert!(manifest.remediations.is_empty());
    }

    // ─── Encryption tests ───────────────────────────────────────────────

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // This test requires /etc/machine-id to exist (present on all Linux systems)
        if std::fs::read_to_string("/etc/machine-id").is_err() {
            eprintln!("Skipping encryption test: /etc/machine-id not available");
            return;
        }

        let original = "sk-ant-api03-REALKEY1234567890abcdef";
        let encrypted = encrypt_key(original).expect("encryption should succeed");

        // Ciphertext should be non-empty base64
        assert!(!encrypted.ciphertext.is_empty());
        // Salt should be 32 hex chars (16 bytes)
        assert_eq!(encrypted.salt.len(), 32);

        let decrypted = decrypt_key(&encrypted).expect("decryption should succeed");
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_encrypt_different_salts() {
        if std::fs::read_to_string("/etc/machine-id").is_err() {
            eprintln!("Skipping encryption test: /etc/machine-id not available");
            return;
        }

        let key = "sk-ant-api03-TESTKEY0123456789abcdef";
        let enc1 = encrypt_key(key).expect("first encryption should succeed");
        let enc2 = encrypt_key(key).expect("second encryption should succeed");

        // Different salts
        assert_ne!(enc1.salt, enc2.salt);
        // Different ciphertexts (due to different salts/nonces)
        assert_ne!(enc1.ciphertext, enc2.ciphertext);

        // Both should decrypt to the same value
        assert_eq!(
            decrypt_key(&enc1).unwrap(),
            decrypt_key(&enc2).unwrap()
        );
    }

    // ─── Provider detection tests ───────────────────────────────────────

    #[test]
    fn test_provider_from_json_path_slack() {
        let (provider, upstream) =
            detect_provider_from_context("channels.slack.bot_token", "xoxb-something");
        assert_eq!(provider, "slack");
        assert_eq!(upstream, "https://slack.com/api");
    }

    #[test]
    fn test_provider_from_json_path_anthropic() {
        let (provider, upstream) =
            detect_provider_from_context("providers.anthropic.api_key", "sk-ant-whatever");
        assert_eq!(provider, "anthropic");
        assert_eq!(upstream, "https://api.anthropic.com");
    }

    #[test]
    fn test_provider_prefix_fallback() {
        // Unknown path, but key prefix is recognizable
        let (provider, upstream) = detect_provider_from_context(
            "some.unknown.path",
            "sk-ant-api03-ABCDEF1234567890",
        );
        assert_eq!(provider, "anthropic");
        assert_eq!(upstream, "https://api.anthropic.com");
    }

    #[test]
    fn test_provider_unknown() {
        let (provider, upstream) =
            detect_provider_from_context("some.unknown.path", "totally-unknown-key-format");
        assert_eq!(provider, "unknown");
        assert_eq!(upstream, "");
    }

    // ─── JSON key extraction tests ──────────────────────────────────────

    #[test]
    fn test_extract_keys_from_json() {
        let json = r#"{
            "providers": {
                "anthropic": {
                    "api_key": "sk-ant-api03-REALKEY1234567890abcdef"
                },
                "openai": {
                    "api_key": "sk-proj-ABCDEFGHIJKLMNOP1234567890"
                }
            },
            "name": "not-a-key"
        }"#;

        let keys = extract_keys_from_json(json);
        assert_eq!(keys.len(), 2, "Should find exactly 2 keys");

        // Check that paths are correct
        let paths: Vec<&str> = keys.iter().map(|k| k.json_path.as_str()).collect();
        assert!(paths.contains(&"providers.anthropic.api_key"));
        assert!(paths.contains(&"providers.openai.api_key"));

        // Check prefixes
        let anthropic_key = keys.iter().find(|k| k.prefix == "sk-ant-").unwrap();
        assert!(anthropic_key.full_key.starts_with("sk-ant-"));

        let openai_key = keys.iter().find(|k| k.prefix == "sk-proj-").unwrap();
        assert!(openai_key.full_key.starts_with("sk-proj-"));
    }

    #[test]
    fn test_extract_keys_no_keys() {
        let json = r#"{
            "name": "my-app",
            "version": "1.0",
            "debug": true,
            "count": 42,
            "tags": ["foo", "bar"]
        }"#;

        let keys = extract_keys_from_json(json);
        assert!(keys.is_empty(), "Should find no keys in benign JSON");
    }

    #[test]
    fn test_extract_keys_short_key_ignored() {
        let json = r#"{
            "short": "sk-ant-tooshort",
            "also_short": "sk-tiny"
        }"#;

        let keys = extract_keys_from_json(json);
        assert!(
            keys.is_empty(),
            "Keys with fewer than 16 chars after prefix should be ignored"
        );
    }

    // ─── YAML key extraction tests ──────────────────────────────────────

    #[test]
    fn test_extract_keys_from_yaml() {
        let yaml = r#"
providers:
  anthropic:
    api_key: "sk-ant-api03-REALKEY1234567890abcdef"
  groq:
    api_key: "gsk_ABCDEFGHIJKLMNOPQRSTUVWX"
name: not-a-key
"#;

        let keys = extract_keys_from_yaml(yaml);
        assert_eq!(keys.len(), 2, "Should find exactly 2 keys in YAML");

        let paths: Vec<&str> = keys.iter().map(|k| k.json_path.as_str()).collect();
        assert!(paths.contains(&"providers.anthropic.api_key"));
        assert!(paths.contains(&"providers.groq.api_key"));
    }

    // ─── JSON rewriting tests ───────────────────────────────────────────

    #[test]
    fn test_rewrite_json_key() {
        let json = r#"{
  "providers": {
    "anthropic": {
      "api_key": "sk-ant-api03-REALKEY1234567890abcdef"
    }
  }
}"#;

        let result =
            rewrite_json_key(json, "providers.anthropic.api_key", "vk-remediated-001").unwrap();

        // Should contain the new value
        assert!(result.contains("vk-remediated-001"));
        // Should NOT contain the old value
        assert!(!result.contains("sk-ant-api03-REALKEY1234567890abcdef"));
        // Should still be valid JSON with the structure preserved
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(
            parsed["providers"]["anthropic"]["api_key"],
            "vk-remediated-001"
        );
    }

    #[test]
    fn test_rewrite_json_key_missing_path() {
        let json = r#"{"a": {"b": 1}}"#;
        let result = rewrite_json_key(json, "a.c.d", "new-value");
        assert!(result.is_err(), "Should error on missing path");
    }

    // ─── YAML rewriting tests ───────────────────────────────────────────

    #[test]
    fn test_rewrite_yaml_key() {
        let yaml = "providers:\n  anthropic:\n    api_key: \"sk-ant-api03-REALKEY1234567890abcdef\"\n  openai:\n    api_key: \"sk-proj-ABCDEFGHIJKLMNOP1234567890\"\n";

        let result = rewrite_yaml_key(
            yaml,
            "sk-ant-api03-REALKEY1234567890abcdef",
            "vk-remediated-001",
        )
        .unwrap();

        assert!(result.contains("vk-remediated-001"));
        assert!(!result.contains("sk-ant-api03-REALKEY1234567890abcdef"));
        // OpenAI key should be untouched
        assert!(result.contains("sk-proj-ABCDEFGHIJKLMNOP1234567890"));
    }

    // ─── Proxy overlay tests ────────────────────────────────────────────

    #[test]
    fn test_write_proxy_overlay() {
        let dir = tempfile::tempdir().unwrap();
        let overlay_path = dir.path().join("90-remediated-keys.toml");
        let overlay_str = overlay_path.to_str().unwrap();

        let entries = vec![RemediationEntry {
            id: "test-001".to_string(),
            timestamp: "2026-02-19T12:00:00Z".to_string(),
            source_file: "/home/openclaw/.openclaw/openclaw.json".to_string(),
            json_path: "providers.anthropic.api_key".to_string(),
            original_key_prefix: "sk-ant-".to_string(),
            original_key_hash: "abcdef1234567890".to_string(),
            encrypted_real_key: "base64ciphertext==".to_string(),
            encryption_salt: "aabbccdd00112233".to_string(),
            virtual_key: "vk-remediated-001".to_string(),
            provider: "anthropic".to_string(),
            upstream: "https://api.anthropic.com".to_string(),
        }];

        let real_keys = vec!["sk-ant-api03-REALKEY1234567890abcdef".to_string()];

        write_proxy_overlay(overlay_str, &entries, &real_keys).unwrap();

        let content = std::fs::read_to_string(overlay_str).unwrap();
        assert!(content.contains("vk-remediated-001"), "Should contain virtual key");
        assert!(
            content.contains("sk-ant-api03-REALKEY1234567890abcdef"),
            "Should contain real key"
        );
        assert!(content.contains("anthropic"), "Should contain provider");
        assert!(
            content.contains("https://api.anthropic.com"),
            "Should contain upstream"
        );
        assert!(
            content.contains("key_mapping"),
            "Should have key_mapping section"
        );

        // Verify the TOML is parseable
        let parsed: toml::Value = toml::from_str(&content).unwrap();
        let mappings = parsed["proxy"]["key_mapping"].as_array().unwrap();
        assert_eq!(mappings.len(), 1);
    }

    #[test]
    fn test_write_proxy_overlay_appends() {
        let dir = tempfile::tempdir().unwrap();
        let overlay_path = dir.path().join("90-remediated-keys.toml");
        let overlay_str = overlay_path.to_str().unwrap();

        // First write
        let entries1 = vec![RemediationEntry {
            id: "test-001".to_string(),
            timestamp: "2026-02-19T12:00:00Z".to_string(),
            source_file: "/home/openclaw/.openclaw/openclaw.json".to_string(),
            json_path: "providers.anthropic.api_key".to_string(),
            original_key_prefix: "sk-ant-".to_string(),
            original_key_hash: "abcdef1234567890".to_string(),
            encrypted_real_key: "base64ciphertext==".to_string(),
            encryption_salt: "aabbccdd00112233".to_string(),
            virtual_key: "vk-remediated-001".to_string(),
            provider: "anthropic".to_string(),
            upstream: "https://api.anthropic.com".to_string(),
        }];
        let real_keys1 = vec!["sk-ant-api03-REALKEY1234567890abcdef".to_string()];
        write_proxy_overlay(overlay_str, &entries1, &real_keys1).unwrap();

        // Second write with a different entry
        let entries2 = vec![RemediationEntry {
            id: "test-002".to_string(),
            timestamp: "2026-02-19T13:00:00Z".to_string(),
            source_file: "/home/openclaw/.openclaw/openclaw.json".to_string(),
            json_path: "providers.openai.api_key".to_string(),
            original_key_prefix: "sk-proj-".to_string(),
            original_key_hash: "fedcba0987654321".to_string(),
            encrypted_real_key: "othercipher==".to_string(),
            encryption_salt: "11223344aabbccdd".to_string(),
            virtual_key: "vk-remediated-002".to_string(),
            provider: "openai".to_string(),
            upstream: "https://api.openai.com".to_string(),
        }];
        let real_keys2 = vec!["sk-proj-ABCDEFGHIJKLMNOP1234567890".to_string()];
        write_proxy_overlay(overlay_str, &entries2, &real_keys2).unwrap();

        // Verify both mappings are present
        let content = std::fs::read_to_string(overlay_str).unwrap();
        assert!(content.contains("vk-remediated-001"), "First mapping should still be present");
        assert!(content.contains("vk-remediated-002"), "Second mapping should be added");

        let parsed: toml::Value = toml::from_str(&content).unwrap();
        let mappings = parsed["proxy"]["key_mapping"].as_array().unwrap();
        assert_eq!(mappings.len(), 2, "Should have exactly 2 mappings after append");
    }
}
