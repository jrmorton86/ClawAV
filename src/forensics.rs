// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

#![allow(dead_code)]
//! Forensic dump capture and incident response actions.
//!
//! Implements §9 (Forensic Dump Format) and §8.2-8.3 (Response Actions / Escalation Chains)
//! from the predictive interception design document.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::safe_io::{atomic_write, mkdir_safe, redact_env};

/// Default output directory for forensic dumps.
pub const DEFAULT_FORENSICS_DIR: &str = "/var/lib/clawtower/forensics";

// ─── Forensic Dump ───────────────────────────────────────────────────────────

/// A complete incident snapshot captured from /proc at the moment of detection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ForensicDump {
    /// When the dump was captured.
    pub timestamp: DateTime<Utc>,
    /// Target process ID.
    pub pid: u32,
    /// Accumulated threat score at time of capture.
    pub threat_score: f64,
    /// Threat state string (e.g. "ELEVATED", "CRITICAL", "LOCKDOWN").
    pub threat_state: String,
    /// Contents of /proc/[pid]/maps.
    pub memory_maps: Option<String>,
    /// Open file descriptors: fd number → symlink target.
    pub open_fds: Vec<FdInfo>,
    /// Active network connections parsed from /proc/[pid]/net/tcp{,6}.
    pub network_connections: Vec<ConnectionInfo>,
    /// Environment variables from /proc/[pid]/environ.
    pub environment: HashMap<String, String>,
    /// Command line from /proc/[pid]/cmdline.
    pub cmdline: Option<String>,
    /// Description of the pattern/event that triggered this dump.
    pub trigger_pattern: String,
}

/// Information about an open file descriptor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FdInfo {
    pub fd: u32,
    pub target: String,
}

/// A parsed network connection from /proc/net/tcp.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConnectionInfo {
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
}

// ─── /proc helpers ───────────────────────────────────────────────────────────

fn read_proc_file(pid: u32, name: &str) -> Option<String> {
    fs::read_to_string(format!("/proc/{}/{}", pid, name)).ok()
}

fn read_proc_bytes(pid: u32, name: &str) -> Option<Vec<u8>> {
    fs::read(format!("/proc/{}/{}", pid, name)).ok()
}

fn read_memory_maps(pid: u32) -> Option<String> {
    read_proc_file(pid, "maps")
}

fn read_cmdline(pid: u32) -> Option<String> {
    read_proc_bytes(pid, "cmdline").map(|b| {
        b.split(|&c| c == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect::<Vec<_>>()
            .join(" ")
    })
}

fn read_environ(pid: u32) -> HashMap<String, String> {
    let Some(data) = read_proc_bytes(pid, "environ") else {
        return HashMap::new();
    };
    data.split(|&c| c == 0)
        .filter(|s| !s.is_empty())
        .filter_map(|entry| {
            let s = String::from_utf8_lossy(entry);
            let idx = s.find('=')?;
            Some((s[..idx].to_string(), s[idx + 1..].to_string()))
        })
        .collect()
}

fn enumerate_fds(pid: u32) -> Vec<FdInfo> {
    let dir = format!("/proc/{}/fd", pid);
    let Ok(entries) = fs::read_dir(&dir) else {
        return Vec::new();
    };
    entries
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let fd: u32 = e.file_name().to_str()?.parse().ok()?;
            let target = fs::read_link(e.path()).ok()?;
            Some(FdInfo {
                fd,
                target: target.to_string_lossy().into_owned(),
            })
        })
        .collect()
}

/// Parse a hex IP:port pair from /proc/net/tcp format (little-endian hex).
fn parse_hex_addr(hex: &str) -> Option<String> {
    let mut parts = hex.split(':');
    let ip_hex = parts.next()?;
    let port_hex = parts.next()?;
    if ip_hex.len() == 8 {
        // IPv4
        let ip_u32 = u32::from_str_radix(ip_hex, 16).ok()?;
        let _ip = Ipv4Addr::from(ip_u32.to_be());
        // /proc/net/tcp stores IP in host byte order (little-endian on LE machines)
        // Reconstruct as network order
        let octets = [
            (ip_u32 & 0xFF) as u8,
            ((ip_u32 >> 8) & 0xFF) as u8,
            ((ip_u32 >> 16) & 0xFF) as u8,
            ((ip_u32 >> 24) & 0xFF) as u8,
        ];
        let port = u16::from_str_radix(port_hex, 16).ok()?;
        Some(format!("{}.{}.{}.{}:{}", octets[0], octets[1], octets[2], octets[3], port))
    } else {
        // IPv6 — just format as hex:port
        let port = u16::from_str_radix(port_hex, 16).ok()?;
        Some(format!("[{}]:{}", ip_hex, port))
    }
}

/// TCP state number to human-readable name.
fn tcp_state_name(state: u8) -> &'static str {
    match state {
        0x01 => "ESTABLISHED",
        0x02 => "SYN_SENT",
        0x03 => "SYN_RECV",
        0x04 => "FIN_WAIT1",
        0x05 => "FIN_WAIT2",
        0x06 => "TIME_WAIT",
        0x07 => "CLOSE",
        0x08 => "CLOSE_WAIT",
        0x09 => "LAST_ACK",
        0x0A => "LISTEN",
        0x0B => "CLOSING",
        _ => "UNKNOWN",
    }
}

/// Parse /proc/net/tcp (or tcp6) content into ConnectionInfo entries.
pub fn parse_proc_net_tcp(content: &str) -> Vec<ConnectionInfo> {
    content
        .lines()
        .skip(1) // header line
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 {
                return None;
            }
            let local = parse_hex_addr(fields[1])?;
            let remote = parse_hex_addr(fields[2])?;
            let state_num = u8::from_str_radix(fields[3], 16).ok()?;
            Some(ConnectionInfo {
                local_addr: local,
                remote_addr: remote,
                state: tcp_state_name(state_num).to_string(),
            })
        })
        .collect()
}

fn read_network_connections(pid: u32) -> Vec<ConnectionInfo> {
    let mut conns = Vec::new();
    for proto in &["net/tcp", "net/tcp6"] {
        if let Some(content) = read_proc_file(pid, proto) {
            conns.extend(parse_proc_net_tcp(&content));
        }
    }
    conns
}

// ─── Capture & Save ──────────────────────────────────────────────────────────

/// Capture a forensic dump for the given process.
///
/// Reads all available /proc data. Fields that fail due to EPERM or other
/// errors are set to None/empty rather than failing the whole dump.
pub fn capture_dump(
    pid: u32,
    threat_score: f64,
    threat_state: &str,
    trigger: &str,
) -> anyhow::Result<ForensicDump> {
    Ok(ForensicDump {
        timestamp: Utc::now(),
        pid,
        threat_score,
        threat_state: threat_state.to_string(),
        memory_maps: read_memory_maps(pid),
        open_fds: enumerate_fds(pid),
        network_connections: read_network_connections(pid),
        environment: redact_env(&read_environ(pid)),
        cmdline: read_cmdline(pid),
        trigger_pattern: trigger.to_string(),
    })
}

/// Serialize a forensic dump to JSON and write it to the given directory.
///
/// Creates the output directory if it doesn't exist.
/// Returns the path to the written file.
pub fn save_dump(dump: &ForensicDump, output_dir: &Path) -> anyhow::Result<PathBuf> {
    mkdir_safe(output_dir, 0o700)?;
    let ts = dump.timestamp.format("%Y%m%dT%H%M%SZ");
    let filename = format!("incident-{}-{}.json", ts, dump.pid);
    let path = output_dir.join(filename);
    let json = serde_json::to_string_pretty(dump)?;
    atomic_write(&path, json.as_bytes(), 0o600)?;
    Ok(path)
}

// ─── Response Actions (§8.2) ─────────────────────────────────────────────────

/// Signal type for kill actions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Signal {
    Term,
    Kill,
    Stop,
}

/// Severity level for alerts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Warning,
    Critical,
    Emergency,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Warning => write!(f, "WARNING"),
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::Emergency => write!(f, "EMERGENCY"),
        }
    }
}

/// Response actions the sentinel can take, per §8.2.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Action {
    /// Log the event.
    Log { message: String },
    /// Send an alert notification.
    Alert { severity: Severity, message: String },
    /// Increase monitoring granularity.
    Elevate { new_scan_interval: Duration },
    /// Inject delays into the target process.
    Throttle { delay_us: u64 },
    /// Force threat level in libclawtower via shared memory.
    ForceThreatLevel { level: u16 },
    /// Kill a specific process.
    Kill { pid: u32, signal: Signal },
    /// Freeze entire cgroup.
    Freeze,
    /// Isolate the process network.
    NetworkIsolate,
    /// Corrupt detected payload in memory.
    CorruptPayload { pid: u32, addr: u64, len: usize },
    /// Rotate a hardware watchpoint to a new address.
    RotateWatchpoint { slot: u8, new_addr: u64 },
    /// Capture a forensic dump.
    ForensicDump { pid: u32 },
}

// ─── Escalation Chains (§8.3) ────────────────────────────────────────────────

/// Return the pre-defined escalation action sequence for the given threat state.
///
/// States: "ELEVATED", "CRITICAL", "LOCKDOWN". Other states return an empty vec.
pub fn escalation_chain(threat_state: &str) -> Vec<Action> {
    match threat_state {
        "ELEVATED" => vec![
            Action::Alert {
                severity: Severity::Warning,
                message: "Threat level ELEVATED".to_string(),
            },
            Action::Elevate {
                new_scan_interval: Duration::from_secs(5),
            },
            Action::ForceThreatLevel { level: 300 },
            Action::RotateWatchpoint {
                slot: 4,
                new_addr: 0,
            },
        ],
        "CRITICAL" => vec![
            Action::Alert {
                severity: Severity::Critical,
                message: "Threat level CRITICAL".to_string(),
            },
            Action::Throttle { delay_us: 50_000 },
            Action::Elevate {
                new_scan_interval: Duration::from_millis(500),
            },
            Action::ForceThreatLevel { level: 600 },
            Action::ForensicDump { pid: 0 },
            Action::Kill {
                pid: 0,
                signal: Signal::Kill,
            },
        ],
        "LOCKDOWN" => vec![
            Action::ForensicDump { pid: 0 },
            Action::Freeze,
            Action::NetworkIsolate,
            Action::CorruptPayload {
                pid: 0,
                addr: 0,
                len: 0,
            },
            Action::Alert {
                severity: Severity::Emergency,
                message: "LOCKDOWN — awaiting human review".to_string(),
            },
        ],
        _ => Vec::new(),
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::process;

    #[test]
    fn test_capture_dump_self() {
        let pid = process::id();
        let dump = capture_dump(pid, 500.0, "CRITICAL", "test pattern").unwrap();
        assert_eq!(dump.pid, pid);
        assert_eq!(dump.threat_score, 500.0);
        assert_eq!(dump.threat_state, "CRITICAL");
        // Should be able to read our own maps
        assert!(dump.memory_maps.is_some());
        assert!(dump.cmdline.is_some());
    }

    #[test]
    fn test_fd_enumeration_self() {
        let fds = enumerate_fds(process::id());
        // We should have at least stdin/stdout/stderr
        assert!(fds.len() >= 3, "expected at least 3 fds, got {}", fds.len());
        let fd_nums: Vec<u32> = fds.iter().map(|f| f.fd).collect();
        assert!(fd_nums.contains(&0)); // stdin
        assert!(fd_nums.contains(&1)); // stdout
        assert!(fd_nums.contains(&2)); // stderr
    }

    #[test]
    fn test_parse_proc_net_tcp() {
        let sample = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0050 0100007F:C000 01 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 100 0 0 10 0";

        let conns = parse_proc_net_tcp(sample);
        assert_eq!(conns.len(), 2);

        assert_eq!(conns[0].local_addr, "127.0.0.1:8080");
        assert_eq!(conns[0].remote_addr, "0.0.0.0:0");
        assert_eq!(conns[0].state, "LISTEN");

        assert_eq!(conns[1].local_addr, "127.0.0.1:80");
        assert_eq!(conns[1].remote_addr, "127.0.0.1:49152");
        assert_eq!(conns[1].state, "ESTABLISHED");
    }

    #[test]
    fn test_serialization_roundtrip() {
        let dump = ForensicDump {
            timestamp: Utc::now(),
            pid: 1234,
            threat_score: 750.0,
            threat_state: "CRITICAL".to_string(),
            memory_maps: Some("map data".to_string()),
            open_fds: vec![FdInfo {
                fd: 0,
                target: "/dev/null".to_string(),
            }],
            network_connections: vec![ConnectionInfo {
                local_addr: "127.0.0.1:80".to_string(),
                remote_addr: "10.0.0.1:12345".to_string(),
                state: "ESTABLISHED".to_string(),
            }],
            environment: [("PATH".to_string(), "/usr/bin".to_string())]
                .into_iter()
                .collect(),
            cmdline: Some("test --flag".to_string()),
            trigger_pattern: "test trigger".to_string(),
        };

        let json = serde_json::to_string(&dump).unwrap();
        let restored: ForensicDump = serde_json::from_str(&json).unwrap();
        assert_eq!(dump, restored);
    }

    #[test]
    fn test_save_dump_writes_json() {
        let dump = ForensicDump {
            timestamp: Utc::now(),
            pid: 9999,
            threat_score: 100.0,
            threat_state: "ELEVATED".to_string(),
            memory_maps: None,
            open_fds: Vec::new(),
            network_connections: Vec::new(),
            environment: HashMap::new(),
            cmdline: None,
            trigger_pattern: "test".to_string(),
        };

        let tmp = std::env::temp_dir().join(format!("clawtower_test_{}", process::id()));
        let path = save_dump(&dump, &tmp).unwrap();
        assert!(path.exists());

        // Verify it's valid JSON and deserializes back
        let content = fs::read_to_string(&path).unwrap();
        let restored: ForensicDump = serde_json::from_str(&content).unwrap();
        assert_eq!(restored.pid, 9999);

        // Cleanup
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_escalation_chain_elevated() {
        let chain = escalation_chain("ELEVATED");
        assert_eq!(chain.len(), 4);
        assert!(matches!(chain[0], Action::Alert { severity: Severity::Warning, .. }));
        assert!(matches!(chain[1], Action::Elevate { .. }));
        assert!(matches!(chain[2], Action::ForceThreatLevel { level: 300 }));
        assert!(matches!(chain[3], Action::RotateWatchpoint { .. }));
    }

    #[test]
    fn test_escalation_chain_critical() {
        let chain = escalation_chain("CRITICAL");
        assert!(chain.len() >= 5);
        assert!(matches!(chain[0], Action::Alert { severity: Severity::Critical, .. }));
        assert!(matches!(chain[1], Action::Throttle { .. }));
        assert!(chain.iter().any(|a| matches!(a, Action::ForensicDump { .. })));
        assert!(chain.iter().any(|a| matches!(a, Action::Kill { .. })));
    }

    #[test]
    fn test_escalation_chain_lockdown() {
        let chain = escalation_chain("LOCKDOWN");
        assert!(chain.len() >= 4);
        assert!(matches!(chain[0], Action::ForensicDump { .. }));
        assert!(matches!(chain[1], Action::Freeze));
        assert!(matches!(chain[2], Action::NetworkIsolate));
        assert!(chain.iter().any(|a| matches!(a, Action::Alert { severity: Severity::Emergency, .. })));
    }

    #[test]
    fn test_escalation_chain_unknown() {
        let chain = escalation_chain("NORMAL");
        assert!(chain.is_empty());
    }

    #[test]
    fn test_graceful_handling_unreadable_proc() {
        // PID 1 (init) — some fields will be EPERM without root
        let dump = capture_dump(1, 0.0, "NORMAL", "test").unwrap();
        assert_eq!(dump.pid, 1);
        // Should not panic; fields may be None/empty
    }
}
