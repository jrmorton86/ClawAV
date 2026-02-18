#![allow(dead_code)]
//! Process Cage — Layer 4 containment for compromised AI agents.
//!
//! Provides cgroup freezing, resource limits, network isolation, PID enumeration,
//! and emergency stop. Every function checks runtime capabilities and falls back
//! gracefully through: cgroup v2 → cgroup v1 → userspace (SIGSTOP / iptables).

use crate::capabilities::PlatformCapabilities;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Result type for process cage operations.
pub type CageResult<T> = Result<T, CageError>;

/// Errors from cage operations.
#[derive(Debug)]
pub enum CageError {
    /// cgroup operation failed
    Cgroup(String),
    /// Network isolation failed
    Network(String),
    /// No capable method available
    NoCap(String),
    /// IO error
    Io(io::Error),
    /// Process signal failed
    Signal(i32, i32), // (pid, errno)
}

impl std::fmt::Display for CageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CageError::Cgroup(s) => write!(f, "cgroup error: {}", s),
            CageError::Network(s) => write!(f, "network isolation error: {}", s),
            CageError::NoCap(s) => write!(f, "no capability: {}", s),
            CageError::Io(e) => write!(f, "io error: {}", e),
            CageError::Signal(pid, errno) => write!(f, "signal to pid {} failed (errno {})", pid, errno),
        }
    }
}

impl std::error::Error for CageError {}

impl From<io::Error> for CageError {
    fn from(e: io::Error) -> Self {
        CageError::Io(e)
    }
}

// ── Resource Limits ─────────────────────────────────────────────────────────

/// Configurable resource limits for caged processes.
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Memory hard cap in bytes (default: 2 GiB)
    pub memory_max: u64,
    /// CPU quota as percentage of total (e.g. 200 = 2 cores). Default: 200
    pub cpu_percent: u32,
    /// CPU period in microseconds for cgroup (default: 100_000)
    pub cpu_period_us: u32,
    /// Max PIDs (default: 256)
    pub pids_max: u32,
    /// IO read bytes/sec (default: 100 MiB/s). None = unlimited.
    pub io_rbps: Option<u64>,
    /// IO write bytes/sec (default: 50 MiB/s). None = unlimited.
    pub io_wbps: Option<u64>,
    /// Block device major:minor for IO limits (default: "8:0")
    pub io_device: String,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            memory_max: 2 * 1024 * 1024 * 1024, // 2 GiB
            cpu_percent: 200,
            cpu_period_us: 100_000,
            pids_max: 256,
            io_rbps: Some(100 * 1024 * 1024),
            io_wbps: Some(50 * 1024 * 1024),
            io_device: "8:0".into(),
        }
    }
}

// ── Freeze / Thaw ───────────────────────────────────────────────────────────

/// Method used for freezing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreezeMethod {
    CgroupV2,
    CgroupV1,
    Sigstop,
}

/// Freeze all processes in the given cgroup. Tries cgroup v2 → v1 → SIGSTOP.
///
/// Returns the method that succeeded.
pub fn freeze_cgroup(cgroup_path: &Path, caps: &PlatformCapabilities) -> CageResult<FreezeMethod> {
    // Try cgroup v2 freeze
    if caps.cgroup_v2 && caps.cgroup_freeze {
        let freeze_file = cgroup_path.join("cgroup.freeze");
        if freeze_file.exists() {
            match fs::write(&freeze_file, "1") {
                Ok(()) => {
                    eprintln!("[cage] FROZEN cgroup v2 at {:?}", cgroup_path);
                    return Ok(FreezeMethod::CgroupV2);
                }
                Err(e) => eprintln!("[cage] cgroup v2 freeze failed: {} — trying fallback", e),
            }
        }
    }

    // Try cgroup v1 freezer
    let v1_state = cgroup_path.join("freezer.state");
    if v1_state.exists() {
        match fs::write(&v1_state, "FROZEN") {
            Ok(()) => {
                eprintln!("[cage] FROZEN cgroup v1 at {:?}", cgroup_path);
                return Ok(FreezeMethod::CgroupV1);
            }
            Err(e) => eprintln!("[cage] cgroup v1 freeze failed: {} — trying SIGSTOP", e),
        }
    }

    // Fallback: SIGSTOP all PIDs in the cgroup
    let pids = list_cgroup_pids(cgroup_path).unwrap_or_default();
    if pids.is_empty() {
        return Err(CageError::Cgroup("no PIDs found and no freeze capability".into()));
    }
    sigstop_pids(&pids)?;
    eprintln!("[cage] SIGSTOP sent to {} processes (fallback)", pids.len());
    Ok(FreezeMethod::Sigstop)
}

/// Thaw (unfreeze) all processes in the given cgroup.
pub fn thaw_cgroup(cgroup_path: &Path, caps: &PlatformCapabilities) -> CageResult<FreezeMethod> {
    // cgroup v2
    if caps.cgroup_v2 && caps.cgroup_freeze {
        let freeze_file = cgroup_path.join("cgroup.freeze");
        if freeze_file.exists() {
            match fs::write(&freeze_file, "0") {
                Ok(()) => return Ok(FreezeMethod::CgroupV2),
                Err(e) => eprintln!("[cage] cgroup v2 thaw failed: {}", e),
            }
        }
    }

    // cgroup v1
    let v1_state = cgroup_path.join("freezer.state");
    if v1_state.exists() {
        match fs::write(&v1_state, "THAWED") {
            Ok(()) => return Ok(FreezeMethod::CgroupV1),
            Err(e) => eprintln!("[cage] cgroup v1 thaw failed: {}", e),
        }
    }

    // SIGCONT fallback
    let pids = list_cgroup_pids(cgroup_path).unwrap_or_default();
    if pids.is_empty() {
        return Err(CageError::Cgroup("no PIDs found and no thaw capability".into()));
    }
    sigcont_pids(&pids)?;
    Ok(FreezeMethod::Sigstop)
}

// ── PID Listing ─────────────────────────────────────────────────────────────

/// List all PIDs in a cgroup by reading cgroup.procs.
pub fn list_cgroup_pids(cgroup_path: &Path) -> CageResult<Vec<i32>> {
    let procs_file = cgroup_path.join("cgroup.procs");
    let content = fs::read_to_string(&procs_file).map_err(|e| {
        CageError::Cgroup(format!("cannot read {:?}: {}", procs_file, e))
    })?;
    let pids: Vec<i32> = content
        .lines()
        .filter_map(|line| line.trim().parse::<i32>().ok())
        .collect();
    Ok(pids)
}

// ── Resource Limits ─────────────────────────────────────────────────────────

/// Apply resource limits to a cgroup. Falls back to setrlimit for non-cgroup environments.
pub fn apply_resource_limits(
    cgroup_path: &Path,
    limits: &ResourceLimits,
    caps: &PlatformCapabilities,
) -> CageResult<()> {
    if caps.cgroup_v2 {
        apply_cgroup_v2_limits(cgroup_path, limits)?;
    } else {
        // setrlimit fallback — applies to current process (sentinel can set on children)
        apply_rlimit_fallback(limits)?;
    }
    Ok(())
}

fn apply_cgroup_v2_limits(cgroup_path: &Path, limits: &ResourceLimits) -> CageResult<()> {
    // memory.max
    let mem_path = cgroup_path.join("memory.max");
    if mem_path.exists() {
        fs::write(&mem_path, limits.memory_max.to_string())?;
    }

    // cpu.max — format: "quota period" in microseconds
    let cpu_path = cgroup_path.join("cpu.max");
    if cpu_path.exists() {
        let quota = (limits.cpu_percent as u64) * (limits.cpu_period_us as u64) / 100;
        fs::write(&cpu_path, format!("{} {}", quota, limits.cpu_period_us))?;
    }

    // pids.max
    let pids_path = cgroup_path.join("pids.max");
    if pids_path.exists() {
        fs::write(&pids_path, limits.pids_max.to_string())?;
    }

    // io.max
    let io_path = cgroup_path.join("io.max");
    if io_path.exists() {
        let mut io_line = limits.io_device.clone();
        if let Some(rbps) = limits.io_rbps {
            io_line.push_str(&format!(" rbps={}", rbps));
        }
        if let Some(wbps) = limits.io_wbps {
            io_line.push_str(&format!(" wbps={}", wbps));
        }
        if limits.io_rbps.is_some() || limits.io_wbps.is_some() {
            fs::write(&io_path, io_line)?;
        }
    }

    Ok(())
}

fn apply_rlimit_fallback(limits: &ResourceLimits) -> CageResult<()> {
    // RLIMIT_AS (address space ~ memory)
    let mem_rlimit = libc::rlimit {
        rlim_cur: limits.memory_max,
        rlim_max: limits.memory_max,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_AS, &mem_rlimit) } != 0 {
        eprintln!("[cage] setrlimit RLIMIT_AS failed: {}", io::Error::last_os_error());
    }

    // RLIMIT_NPROC (max child processes ~ pids)
    let nproc_rlimit = libc::rlimit {
        rlim_cur: limits.pids_max as u64,
        rlim_max: limits.pids_max as u64,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &nproc_rlimit) } != 0 {
        eprintln!("[cage] setrlimit RLIMIT_NPROC failed: {}", io::Error::last_os_error());
    }

    // Note: no direct CPU limit via rlimit; cpu_percent is cgroup-only
    Ok(())
}

// ── Network Isolation ───────────────────────────────────────────────────────

/// Network isolation method used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetIsolationMethod {
    Namespace,
    Nftables,
    Iptables,
}

/// Isolate a process's network. Prefers network namespace; falls back to iptables DROP.
pub fn isolate_network(pid: i32, caps: &PlatformCapabilities) -> CageResult<NetIsolationMethod> {
    if caps.network_namespaces {
        match isolate_via_netns(pid) {
            Ok(()) => return Ok(NetIsolationMethod::Namespace),
            Err(e) => eprintln!("[cage] netns isolation failed: {} — trying nftables/iptables", e),
        }
    }

    // Fallback: nftables/iptables DROP rules for the process's UID
    if command_exists("nft") {
        match isolate_via_nftables(pid) {
            Ok(()) => return Ok(NetIsolationMethod::Nftables),
            Err(e) => eprintln!("[cage] nftables isolation failed: {} — trying iptables", e),
        }
    }

    if !command_exists("iptables") {
        return Err(CageError::NoCap("no supported packet filter backend (nft/iptables)".into()));
    }

    isolate_via_iptables(pid)?;
    Ok(NetIsolationMethod::Iptables)
}

fn command_exists(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Select which isolation method would be used (for testing/dry-run).
pub fn select_net_isolation_method(caps: &PlatformCapabilities) -> NetIsolationMethod {
    if caps.network_namespaces {
        NetIsolationMethod::Namespace
    } else {
        NetIsolationMethod::Iptables
    }
}

fn isolate_via_netns(pid: i32) -> CageResult<()> {
    let ns_name = format!("clawjail_{}", pid);

    // Create new network namespace
    let status = Command::new("ip")
        .args(["netns", "add", &ns_name])
        .status()
        .map_err(|e| CageError::Network(format!("ip netns add: {}", e)))?;
    if !status.success() {
        return Err(CageError::Network(format!(
            "ip netns add failed with code {:?}",
            status.code()
        )));
    }

    // Move process into the namespace via nsenter
    let status = Command::new("nsenter")
        .args([
            &format!("--net=/var/run/netns/{}", ns_name),
            "--target",
            &pid.to_string(),
        ])
        .status()
        .map_err(|e| CageError::Network(format!("nsenter: {}", e)))?;
    if !status.success() {
        // Clean up on failure
        let _ = Command::new("ip").args(["netns", "del", &ns_name]).status();
        return Err(CageError::Network(format!(
            "nsenter failed with code {:?}",
            status.code()
        )));
    }

    eprintln!("[cage] Process {} moved to network namespace {}", pid, ns_name);
    Ok(())
}

fn isolate_via_iptables(pid: i32) -> CageResult<()> {
    // Read UID of the target process
    let status_path = format!("/proc/{}/status", pid);
    let status_content = fs::read_to_string(&status_path)
        .map_err(|e| CageError::Network(format!("cannot read {}: {}", status_path, e)))?;

    let uid = status_content
        .lines()
        .find(|l| l.starts_with("Uid:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or_else(|| CageError::Network("cannot determine UID".into()))?;

    // Add DROP rules for this UID (OUTPUT chain blocks all outgoing)
    let comment = format!("clawtower_cage_{}", pid);
    let status = Command::new("iptables")
        .args([
            "-A", "OUTPUT",
            "-m", "owner", "--uid-owner", &uid.to_string(),
            "-j", "DROP",
            "-m", "comment", "--comment", &comment,
        ])
        .status()
        .map_err(|e| CageError::Network(format!("iptables: {}", e)))?;

    if !status.success() {
        return Err(CageError::Network("iptables DROP rule failed".into()));
    }

    eprintln!("[cage] iptables DROP for UID {} (pid {})", uid, pid);
    Ok(())
}

fn isolate_via_nftables(pid: i32) -> CageResult<()> {
    // Read UID of the target process
    let status_path = format!("/proc/{}/status", pid);
    let status_content = fs::read_to_string(&status_path)
        .map_err(|e| CageError::Network(format!("cannot read {}: {}", status_path, e)))?;

    let uid = status_content
        .lines()
        .find(|l| l.starts_with("Uid:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or_else(|| CageError::Network("cannot determine UID".into()))?;

    // Ensure table/chain exist (ignore already-exists errors)
    let _ = Command::new("nft")
        .args(["add", "table", "inet", "clawtower_cage"])
        .status();

    let _ = Command::new("bash")
        .args([
            "-c",
            "nft add chain inet clawtower_cage output '{ type filter hook output priority 0 ; policy accept ; }'",
        ])
        .status();

    let comment = format!("clawtower_cage_{}", pid);
    let status = Command::new("nft")
        .args([
            "add", "rule", "inet", "clawtower_cage", "output",
            "meta", "skuid", &uid.to_string(),
            "drop", "comment", &comment,
        ])
        .status()
        .map_err(|e| CageError::Network(format!("nft: {}", e)))?;

    if !status.success() {
        return Err(CageError::Network("nftables DROP rule failed".into()));
    }

    eprintln!("[cage] nftables DROP for UID {} (pid {})", uid, pid);
    Ok(())
}

// ── Emergency Stop ──────────────────────────────────────────────────────────

/// Emergency stop result showing what actions were taken.
#[derive(Debug)]
pub struct EmergencyStopResult {
    pub frozen: Option<FreezeMethod>,
    pub network_isolated: Option<NetIsolationMethod>,
    pub errors: Vec<String>,
}

/// Emergency stop: freeze → SIGSTOP → network isolate.
/// Uses whatever capabilities are available. Best-effort, never panics.
pub fn emergency_stop(
    pid: i32,
    cgroup_path: Option<&Path>,
    caps: &PlatformCapabilities,
) -> EmergencyStopResult {
    let mut result = EmergencyStopResult {
        frozen: None,
        network_isolated: None,
        errors: Vec::new(),
    };

    // Step 1: Freeze cgroup (or SIGSTOP)
    if let Some(cg) = cgroup_path {
        match freeze_cgroup(cg, caps) {
            Ok(method) => result.frozen = Some(method),
            Err(e) => {
                result.errors.push(format!("freeze: {}", e));
                // Direct SIGSTOP on the target pid as last resort
                if unsafe { libc::kill(pid, libc::SIGSTOP) } == 0 {
                    result.frozen = Some(FreezeMethod::Sigstop);
                } else {
                    result.errors.push(format!("SIGSTOP pid {}: {}", pid, io::Error::last_os_error()));
                }
            }
        }
    } else {
        // No cgroup path — direct SIGSTOP
        if unsafe { libc::kill(pid, libc::SIGSTOP) } == 0 {
            result.frozen = Some(FreezeMethod::Sigstop);
        } else {
            result.errors.push(format!("SIGSTOP pid {}: {}", pid, io::Error::last_os_error()));
        }
    }

    // Step 2: Network isolation
    match isolate_network(pid, caps) {
        Ok(method) => result.network_isolated = Some(method),
        Err(e) => result.errors.push(format!("network: {}", e)),
    }

    result
}

// ── Signal Helpers ──────────────────────────────────────────────────────────

fn sigstop_pids(pids: &[i32]) -> CageResult<()> {
    let mut last_err = None;
    for &pid in pids {
        if unsafe { libc::kill(pid, libc::SIGSTOP) } != 0 {
            last_err = Some(CageError::Signal(pid, unsafe { *libc::__errno_location() }));
        }
    }
    match last_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

fn sigcont_pids(pids: &[i32]) -> CageResult<()> {
    let mut last_err = None;
    for &pid in pids {
        if unsafe { libc::kill(pid, libc::SIGCONT) } != 0 {
            last_err = Some(CageError::Signal(pid, unsafe { *libc::__errno_location() }));
        }
    }
    match last_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Get the cgroup path for a given PID from /proc/[pid]/cgroup.
pub fn cgroup_path_for_pid(pid: i32) -> Option<PathBuf> {
    let content = fs::read_to_string(format!("/proc/{}/cgroup", pid)).ok()?;
    for line in content.lines() {
        // cgroup v2: "0::/path"
        if let Some(path) = line.strip_prefix("0::") {
            return Some(PathBuf::from(format!("/sys/fs/cgroup{}", path)));
        }
    }
    None
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_caps(cgroup_v2: bool, cgroup_freeze: bool, network_namespaces: bool) -> PlatformCapabilities {
        let mut caps = PlatformCapabilities::probe();
        caps.cgroup_v2 = cgroup_v2;
        caps.cgroup_freeze = cgroup_freeze;
        caps.network_namespaces = network_namespaces;
        caps
    }

    #[test]
    fn test_resource_limits_defaults() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.memory_max, 2 * 1024 * 1024 * 1024);
        assert_eq!(limits.cpu_percent, 200);
        assert_eq!(limits.cpu_period_us, 100_000);
        assert_eq!(limits.pids_max, 256);
        assert_eq!(limits.io_rbps, Some(100 * 1024 * 1024));
        assert_eq!(limits.io_wbps, Some(50 * 1024 * 1024));
        assert_eq!(limits.io_device, "8:0");
    }

    #[test]
    fn test_resource_limits_custom() {
        let limits = ResourceLimits {
            memory_max: 512 * 1024 * 1024,
            cpu_percent: 100,
            pids_max: 64,
            io_rbps: None,
            io_wbps: None,
            ..Default::default()
        };
        assert_eq!(limits.memory_max, 512 * 1024 * 1024);
        assert_eq!(limits.cpu_percent, 100);
        assert_eq!(limits.pids_max, 64);
        assert!(limits.io_rbps.is_none());
    }

    #[test]
    fn test_list_own_cgroup_pids() {
        // Read our own cgroup and list PIDs — should contain at least ourselves
        if let Some(cg) = cgroup_path_for_pid(std::process::id() as i32) {
            match list_cgroup_pids(&cg) {
                Ok(pids) => {
                    assert!(!pids.is_empty(), "our cgroup should have at least 1 pid");
                    let our_pid = std::process::id() as i32;
                    assert!(pids.contains(&our_pid), "our PID should be in the list");
                }
                Err(e) => {
                    // May fail without permissions — that's ok
                    eprintln!("[test] list_cgroup_pids skipped: {}", e);
                }
            }
        } else {
            eprintln!("[test] no cgroup v2 path found — skipping");
        }
    }

    #[test]
    fn test_sigstop_fallback_on_forked_child() {
        // Fork a child, SIGSTOP it, verify it's stopped, then SIGCONT and reap
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0, "fork failed");

            if pid == 0 {
                // Child: sleep forever
                loop {
                    libc::pause();
                }
            }

            // Parent: SIGSTOP the child
            assert_eq!(libc::kill(pid, libc::SIGSTOP), 0);

            // Wait for stop
            let mut status: i32 = 0;
            let ret = libc::waitpid(pid, &mut status, libc::WUNTRACED);
            assert_eq!(ret, pid);
            assert!(libc::WIFSTOPPED(status), "child should be stopped");

            // SIGCONT and then SIGKILL to clean up
            assert_eq!(libc::kill(pid, libc::SIGCONT), 0);
            assert_eq!(libc::kill(pid, libc::SIGKILL), 0);
            libc::waitpid(pid, &mut status, 0);
        }
    }

    #[test]
    fn test_sigstop_pids_helper() {
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0);
            if pid == 0 {
                loop { libc::pause(); }
            }

            // Use our helper
            assert!(sigstop_pids(&[pid]).is_ok());

            let mut status: i32 = 0;
            libc::waitpid(pid, &mut status, libc::WUNTRACED);
            assert!(libc::WIFSTOPPED(status));

            sigcont_pids(&[pid]).unwrap();
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, &mut status, 0);
        }
    }

    #[test]
    fn test_freeze_cgroup_v2_temp() {
        // Only runs if we have cgroup v2, cgroup freeze, and root
        if unsafe { libc::getuid() } != 0 {
            eprintln!("[test] skipping cgroup freeze test (not root)");
            return;
        }
        let caps = PlatformCapabilities::probe();
        if !caps.cgroup_v2 || !caps.cgroup_freeze {
            eprintln!("[test] skipping cgroup freeze test (no cgroup v2/freeze)");
            return;
        }

        // Create a temp cgroup, write our pid in, freeze, verify, thaw
        let test_cg = PathBuf::from("/sys/fs/cgroup/clawtower_test_cage");
        let _ = fs::create_dir(&test_cg);
        // Write a subtree control if needed
        let _ = fs::write(test_cg.join("cgroup.procs"), std::process::id().to_string());

        if test_cg.join("cgroup.freeze").exists() {
            let result = freeze_cgroup(&test_cg, &caps);
            assert!(result.is_ok(), "freeze failed: {:?}", result);
            assert_eq!(result.unwrap(), FreezeMethod::CgroupV2);

            let result = thaw_cgroup(&test_cg, &caps);
            assert!(result.is_ok());

            // Move ourselves back and clean up
            if let Some(orig) = cgroup_path_for_pid(std::process::id() as i32) {
                let _ = fs::write(orig.join("cgroup.procs"), std::process::id().to_string());
            }
        }

        // Clean up
        let _ = fs::remove_dir(&test_cg);
    }

    #[test]
    fn test_emergency_stop_no_cgroup() {
        // Emergency stop without cgroup — should SIGSTOP the child
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0);
            if pid == 0 {
                loop { libc::pause(); }
            }

            let caps = mock_caps(false, false, false);
            let result = emergency_stop(pid, None, &caps);

            // Should have stopped via SIGSTOP
            assert_eq!(result.frozen, Some(FreezeMethod::Sigstop));
            // Network isolation will fail (no netns, iptables needs root) — that's expected
            assert!(!result.errors.is_empty() || result.network_isolated.is_some());

            // Clean up
            libc::kill(pid, libc::SIGCONT);
            libc::kill(pid, libc::SIGKILL);
            let mut status = 0;
            libc::waitpid(pid, &mut status, 0);
        }
    }

    #[test]
    fn test_net_isolation_method_selection() {
        let caps_ns = mock_caps(true, true, true);
        assert_eq!(select_net_isolation_method(&caps_ns), NetIsolationMethod::Namespace);

        let caps_no_ns = mock_caps(true, true, false);
        assert_eq!(select_net_isolation_method(&caps_no_ns), NetIsolationMethod::Iptables);
    }

    #[test]
    fn test_cgroup_path_for_self() {
        // Should find our own cgroup on systems with cgroup v2
        match cgroup_path_for_pid(std::process::id() as i32) {
            Some(path) => {
                assert!(path.to_str().unwrap().contains("/sys/fs/cgroup"));
            }
            None => {
                eprintln!("[test] no cgroup v2 — skipping");
            }
        }
    }

    #[test]
    fn test_cage_error_display() {
        let e = CageError::Cgroup("test".into());
        assert!(e.to_string().contains("test"));

        let e = CageError::Signal(42, 1);
        assert!(e.to_string().contains("42"));
    }

    #[test]
    fn test_freeze_nonexistent_cgroup() {
        let caps = mock_caps(true, true, false);
        let bad_path = Path::new("/sys/fs/cgroup/clawtower_nonexistent_xyzzy");
        let result = freeze_cgroup(bad_path, &caps);
        assert!(result.is_err());
    }
}
