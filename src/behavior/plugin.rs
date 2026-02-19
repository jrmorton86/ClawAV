// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Plugin abuse detection functions.
//!
//! Detects OpenClaw plugin misbehavior: config tampering, unauthorized network
//! listeners, inter-plugin modification, and node_modules poisoning.

use super::patterns::{PLUGIN_CONFIG_PATHS, PLUGIN_PERSISTENCE_PATHS};

/// Detect a plugin attempting to write to OpenClaw config files.
///
/// Matches commands that write to paths in `PLUGIN_CONFIG_PATHS` (e.g., `openclaw.json`,
/// `auth-profiles.json`). Only triggers on write-like commands, not reads.
pub fn is_plugin_config_tampering(cmd: &str) -> bool {
    let write_indicators = ["echo", "tee", "sed -i", "mv ", "cp ", "cat >", ">>", "install ", "> "];
    let has_write = write_indicators.iter().any(|w| cmd.contains(w));
    if !has_write {
        return false;
    }
    PLUGIN_CONFIG_PATHS.iter().any(|path| cmd.contains(path))
}

/// Detect a plugin spawning a network listener.
///
/// Matches `nc -l`, `ncat -l`, `http.createServer`, `http.server`, etc.
pub fn is_plugin_network_listener(cmd: &str) -> bool {
    let listener_patterns = [
        "nc -l", "ncat -l", "netcat -l", "socat TCP-LISTEN",
        "http.createServer", "net.createServer",
        "http.server", "SimpleHTTPServer",
        ".listen(",
    ];
    listener_patterns.iter().any(|p| cmd.contains(p))
}

/// Detect one plugin modifying another plugin's files.
///
/// Checks if a write command targets a path in another plugin's directory
/// (e.g., writing to `extensions/other-plugin/`).
pub fn is_inter_plugin_modification(cmd: &str, file_path: &str) -> bool {
    // Must be a write operation
    let write_cmds = ["echo", "tee", "sed", "mv", "cp", "install", "chmod", "chown", "rm"];
    let binary = cmd.split_whitespace().next().unwrap_or("");
    let base = binary.rsplit('/').next().unwrap_or(binary);
    let is_write = write_cmds.iter().any(|w| base == *w);
    if !is_write {
        return false;
    }

    // Target must be in an extensions directory
    file_path.contains("/extensions/") && file_path.contains("node_modules")
        || (file_path.contains("/extensions/") && file_path.ends_with(".js"))
        || (file_path.contains("/extensions/") && file_path.ends_with(".json"))
}

/// Detect node_modules poisoning — writes to cache, symlink attacks, bin injection.
pub fn is_node_module_poisoning(file_path: &str) -> bool {
    PLUGIN_PERSISTENCE_PATHS.iter().any(|p| file_path.contains(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Config tampering ───────────────────────────────────────────────

    #[test]
    fn test_config_tampering_echo_to_config() {
        assert!(is_plugin_config_tampering("echo '{}' > openclaw.json"));
    }

    #[test]
    fn test_config_tampering_sed_edit() {
        assert!(is_plugin_config_tampering("sed -i 's/old/new/' auth-profiles.json"));
    }

    #[test]
    fn test_config_tampering_cp_overwrite() {
        assert!(is_plugin_config_tampering("cp /tmp/evil.json gateway.yaml"));
    }

    #[test]
    fn test_config_tampering_read_only_ignored() {
        assert!(!is_plugin_config_tampering("cat openclaw.json"));
    }

    #[test]
    fn test_config_tampering_unrelated_file() {
        assert!(!is_plugin_config_tampering("echo 'hello' > notes.txt"));
    }

    #[test]
    fn test_config_tampering_tee() {
        assert!(is_plugin_config_tampering("tee device.json"));
    }

    // ── Network listeners ──────────────────────────────────────────────

    #[test]
    fn test_network_listener_nc() {
        assert!(is_plugin_network_listener("nc -l -p 8080"));
    }

    #[test]
    fn test_network_listener_node_http() {
        assert!(is_plugin_network_listener("node -e 'http.createServer()'"));
    }

    #[test]
    fn test_network_listener_python_http() {
        assert!(is_plugin_network_listener("python3 -m http.server 9090"));
    }

    #[test]
    fn test_network_listener_socat() {
        assert!(is_plugin_network_listener("socat TCP-LISTEN:4444,fork EXEC:/bin/sh"));
    }

    #[test]
    fn test_network_listener_normal_command() {
        assert!(!is_plugin_network_listener("ls -la"));
    }

    #[test]
    fn test_network_listener_net_create_server() {
        assert!(is_plugin_network_listener("node -e 'net.createServer()'"));
    }

    // ── Inter-plugin modification ──────────────────────────────────────

    #[test]
    fn test_inter_plugin_write_js() {
        assert!(is_inter_plugin_modification("cp", "/home/openclaw/.openclaw/extensions/other-plugin/index.js"));
    }

    #[test]
    fn test_inter_plugin_write_json() {
        assert!(is_inter_plugin_modification("sed", "/home/openclaw/.openclaw/extensions/other-plugin/package.json"));
    }

    #[test]
    fn test_inter_plugin_read_ignored() {
        assert!(!is_inter_plugin_modification("cat", "/home/openclaw/.openclaw/extensions/other-plugin/index.js"));
    }

    #[test]
    fn test_inter_plugin_non_extension_path() {
        assert!(!is_inter_plugin_modification("cp", "/home/openclaw/projects/file.js"));
    }

    // ── Node module poisoning ──────────────────────────────────────────

    #[test]
    fn test_node_module_poisoning_bin() {
        assert!(is_node_module_poisoning("/home/openclaw/project/node_modules/.bin/evil"));
    }

    #[test]
    fn test_node_module_poisoning_cache() {
        assert!(is_node_module_poisoning("/home/openclaw/project/node_modules/.cache/something"));
    }

    #[test]
    fn test_node_module_poisoning_npmrc() {
        assert!(is_node_module_poisoning("/home/openclaw/.npmrc"));
    }

    #[test]
    fn test_node_module_poisoning_hooks() {
        assert!(is_node_module_poisoning("/home/openclaw/project/node_modules/.hooks/preinstall"));
    }

    #[test]
    fn test_node_module_poisoning_normal_file() {
        assert!(!is_node_module_poisoning("/home/openclaw/project/src/index.js"));
    }
}
