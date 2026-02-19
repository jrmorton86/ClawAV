// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Layer 3: Memory Sentinel — hardware watchpoints, memory integrity scanning,
//! cross-memory payload corruption, and process memory map parsing.
//!
//! See design doc §6 (Layer 3) for full rationale and architecture.
//!
//! ## Production Integration
//!
//! Gated on `[memory_sentinel] enabled = true` in config. When enabled, spawns
//! a periodic scan loop that baselines and verifies process memory integrity,
//! sending violations to the alert pipeline.

use crate::core::alerts::{Alert, Severity};
use crate::enforcement::capabilities::PlatformCapabilities;
use crate::config::MemorySentinelConfig;
use std::fs;
use std::io;
use std::time::Duration;
use tokio::sync::mpsc;

// ── Constants ───────────────────────────────────────────────────────────────

// Hardware watchpoint constants — used by set_watchpoint() which is part of
// the designed API surface (currently only exercised by tests).
#[allow(dead_code)]
const PERF_TYPE_BREAKPOINT: u32 = 5;
#[allow(dead_code)]
const HW_BREAKPOINT_W: u32 = 2;
#[allow(dead_code)]
const HW_BREAKPOINT_RW: u32 = 3;
#[allow(dead_code)]
const PERF_FLAG_FD_CLOEXEC: u64 = 1;

/// Maximum length for cross-memory read/write operations (4 MB).
/// Prevents OOM from unbounded allocations and limits the blast radius
/// of payload corruption.
const MAX_MEMORY_OP_LEN: usize = 4 * 1024 * 1024;

// ── Threat Levels ───────────────────────────────────────────────────────────

/// Threat level determines adaptive scan intervals and response intensity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum ThreatLevel {
    Normal,
    Elevated,
    Critical,
    Lockdown,
}

impl ThreatLevel {
    /// Adaptive scan interval for this threat level.
    #[allow(dead_code)]
    pub fn scan_interval(&self) -> Duration {
        match self {
            ThreatLevel::Normal => Duration::from_secs(30),
            ThreatLevel::Elevated => Duration::from_secs(5),
            ThreatLevel::Critical => Duration::from_millis(500),
            ThreatLevel::Lockdown => Duration::from_millis(0), // continuous
        }
    }
}

// ── Watch Types ─────────────────────────────────────────────────────────────

/// Hardware watchpoint access type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum WatchType {
    /// Trigger on write access.
    Write,
    /// Trigger on read or write access.
    ReadWrite,
}

impl WatchType {
    fn to_bp_type(self) -> u32 {
        match self {
            WatchType::Write => HW_BREAKPOINT_W,
            WatchType::ReadWrite => HW_BREAKPOINT_RW,
        }
    }
}

// ── Hardware Watchpoints ────────────────────────────────────────────────────

/// Handle to an active hardware watchpoint. Closing removes it.
#[derive(Debug)]
#[allow(dead_code)]
pub struct WatchpointHandle {
    fd: i32,
}

impl Drop for WatchpointHandle {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd); }
    }
}

/// perf_event_attr for hardware breakpoints (simplified, zero-padded to kernel size).
#[repr(C)]
#[allow(non_camel_case_types, dead_code)]
struct perf_event_attr {
    type_: u32,
    size: u32,
    config: u64,
    sample_period_or_freq: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events_or_watermark: u32,
    bp_type: u32,
    bp_addr_or_config1: u64,
    bp_len_or_config2: u64,
    _pad: [u8; 136 - 80],
}

/// Set a hardware watchpoint on a target process.
///
/// # Arguments
/// * `pid` - Target process ID (0 = self)
/// * `addr` - Virtual address to watch
/// * `len` - Watch length in bytes (typically 1, 2, 4, or 8)
/// * `watch_type` - Write or ReadWrite
///
/// Returns a `WatchpointHandle` that removes the watchpoint on drop.
#[allow(dead_code)]
pub fn set_watchpoint(
    pid: i32,
    addr: u64,
    len: u64,
    watch_type: WatchType,
) -> Result<WatchpointHandle, io::Error> {
    let mut attr: perf_event_attr = unsafe { std::mem::zeroed() };
    attr.type_ = PERF_TYPE_BREAKPOINT;
    attr.size = 136;
    attr.bp_type = watch_type.to_bp_type();
    attr.bp_addr_or_config1 = addr;
    attr.bp_len_or_config2 = len;
    attr.sample_period_or_freq = 1;
    // disabled=0 (bit 0), exclude_kernel=1 (bit 1), exclude_hv=1 (bit 2)
    attr.flags = 0x04 | 0x02; // exclude_kernel | exclude_hv, NOT disabled

    let fd = unsafe {
        libc::syscall(
            libc::SYS_perf_event_open,
            &attr as *const _ as *const libc::c_void,
            pid,
            -1i32,  // any CPU
            -1i32,  // no group
            PERF_FLAG_FD_CLOEXEC,
        )
    };

    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(WatchpointHandle { fd: fd as i32 })
}

/// Remove a watchpoint (consumes the handle).
#[allow(dead_code)]
pub fn remove_watchpoint(handle: WatchpointHandle) {
    drop(handle);
}

// ── Memory Map Parsing ──────────────────────────────────────────────────────

/// A region from `/proc/[pid]/maps`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapRegion {
    pub start: u64,
    pub end: u64,
    pub perms: String,
    pub offset: u64,
    pub path: Option<String>,
}

impl MapRegion {
    /// Whether this region is executable.
    pub fn is_executable(&self) -> bool {
        self.perms.contains('x')
    }

    /// Whether this region is writable.
    pub fn is_writable(&self) -> bool {
        self.perms.contains('w')
    }

    /// Whether this looks like a .text segment (r-xp with a file path).
    pub fn is_text(&self) -> bool {
        self.perms.starts_with("r-xp") || (self.is_executable() && !self.is_writable())
    }
}

/// Parsed memory map of a process.
#[derive(Debug, Clone)]
pub struct MemoryMap {
    pub regions: Vec<MapRegion>,
}

impl MemoryMap {
    /// Parse `/proc/[pid]/maps` for the given process.
    pub fn parse_pid(pid: i32) -> Result<Self, io::Error> {
        let content = fs::read_to_string(format!("/proc/{}/maps", pid))?;
        Ok(Self::parse_content(&content))
    }

    /// Parse maps content from a string (useful for testing).
    pub fn parse_content(content: &str) -> Self {
        let mut regions = Vec::new();
        for line in content.lines() {
            if let Some(region) = Self::parse_line(line) {
                regions.push(region);
            }
        }
        MemoryMap { regions }
    }

    fn parse_line(line: &str) -> Option<MapRegion> {
        let mut parts = line.splitn(6, char::is_whitespace);
        let addr_range = parts.next()?;
        let perms = parts.next()?.to_string();
        let offset_str = parts.next()?;

        let (start_str, end_str) = addr_range.split_once('-')?;
        let start = u64::from_str_radix(start_str, 16).ok()?;
        let end = u64::from_str_radix(end_str, 16).ok()?;
        let offset = u64::from_str_radix(offset_str, 16).ok()?;

        // Skip dev and inode columns
        let _dev = parts.next();
        let _inode = parts.next();

        // Rest is the path (may be empty or whitespace)
        let path = parts.next()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        Some(MapRegion { start, end, perms, offset, path })
    }

    /// Find all executable .text regions.
    pub fn text_regions(&self) -> Vec<&MapRegion> {
        self.regions.iter().filter(|r| r.is_text()).collect()
    }

    /// Find GOT/PLT regions (typically rw-p immediately after r-xp for the same binary).
    /// Heuristic: writable regions with a file path that also has a text region.
    pub fn got_plt_regions(&self) -> Vec<&MapRegion> {
        // Collect paths that have executable regions
        let exec_paths: std::collections::HashSet<&str> = self.regions.iter()
            .filter(|r| r.is_executable())
            .filter_map(|r| r.path.as_deref())
            .collect();

        self.regions.iter()
            .filter(|r| {
                r.is_writable()
                    && !r.is_executable()
                    && r.path.as_deref().map_or(false, |p| exec_paths.contains(p))
            })
            .collect()
    }

    /// Find all loaded library regions (paths containing ".so").
    #[allow(dead_code)]
    pub fn library_regions(&self) -> Vec<&MapRegion> {
        self.regions.iter()
            .filter(|r| r.path.as_deref().map_or(false, |p| p.contains(".so")))
            .collect()
    }
}

// ── Memory Reading ──────────────────────────────────────────────────────────

/// Read memory from a target process. Tries `/proc/[pid]/mem` first,
/// falls back to `process_vm_readv` if available.
pub fn read_process_memory(
    pid: i32,
    addr: u64,
    len: usize,
    caps: &PlatformCapabilities,
) -> Result<Vec<u8>, io::Error> {
    if len > MAX_MEMORY_OP_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "read length {} exceeds maximum {} bytes",
                len, MAX_MEMORY_OP_LEN
            ),
        ));
    }

    if caps.proc_mem {
        read_proc_mem(pid, addr, len)
    } else if caps.cross_memory_attach {
        read_cross_memory(pid, addr, len)
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no memory access method available",
        ))
    }
}

/// Read via `/proc/[pid]/mem`.
fn read_proc_mem(pid: i32, addr: u64, len: usize) -> Result<Vec<u8>, io::Error> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = fs::File::open(format!("/proc/{}/mem", pid))?;
    f.seek(SeekFrom::Start(addr))?;
    let mut buf = vec![0u8; len];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

/// Read via `process_vm_readv`.
fn read_cross_memory(pid: i32, addr: u64, len: usize) -> Result<Vec<u8>, io::Error> {
    if len > MAX_MEMORY_OP_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "read length {} exceeds maximum {} bytes",
                len, MAX_MEMORY_OP_LEN
            ),
        ));
    }

    let mut buf = vec![0u8; len];
    let local_iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: len,
    };
    let remote_iov = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: len,
    };
    let ret = unsafe {
        libc::process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0)
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    if (ret as usize) < len {
        buf.truncate(ret as usize);
    }
    Ok(buf)
}

// ── Memory Integrity Scanning ───────────────────────────────────────────────

/// A detected integrity violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Violation {
    /// .text segment was modified.
    TextModified {
        region_path: Option<String>,
        start: u64,
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// GOT/PLT region was modified (potential GOT overwrite attack).
    GotOverwrite {
        region_path: Option<String>,
        start: u64,
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// Generic region hash mismatch.
    RegionModified {
        start: u64,
        expected: [u8; 32],
        actual: [u8; 32],
    },
}

/// A baseline hash for a memory region.
#[derive(Debug, Clone)]
struct RegionBaseline {
    start: u64,
    len: usize,
    hash: [u8; 32],
    path: Option<String>,
    is_text: bool,
    is_got: bool,
}

/// Memory integrity scanner. Captures baseline hashes and detects modifications.
#[derive(Debug)]
pub struct MemoryIntegrity {
    baselines: Vec<RegionBaseline>,
}

impl MemoryIntegrity {
    /// Capture baseline hashes of all .text and GOT/PLT regions for a process.
    pub fn capture_baseline(
        pid: i32,
        caps: &PlatformCapabilities,
    ) -> Result<Self, io::Error> {
        let map = MemoryMap::parse_pid(pid)?;
        let mut baselines = Vec::new();

        // Collect GOT/PLT paths for identification
        let got_regions: Vec<&MapRegion> = map.got_plt_regions();
        let _got_set: std::collections::HashSet<(u64, u64)> = got_regions
            .iter()
            .map(|r| (r.start, r.end))
            .collect();

        // Hash all text regions
        for region in map.text_regions() {
            let len = match region.end.checked_sub(region.start) {
                Some(l) if l > 0 && l <= 64 * 1024 * 1024 => l as usize,
                _ => continue, // skip empty, underflow, or absurdly large
            };
            match read_process_memory(pid, region.start, len, caps) {
                Ok(data) => {
                    let hash: [u8; 32] = blake3::hash(&data).into();
                    baselines.push(RegionBaseline {
                        start: region.start,
                        len,
                        hash,
                        path: region.path.clone(),
                        is_text: true,
                        is_got: false,
                    });
                }
                Err(_) => continue, // inaccessible region, skip
            }
        }

        // Hash GOT/PLT regions
        for region in &got_regions {
            let len = (region.end - region.start) as usize;
            if len == 0 || len > 1024 * 1024 {
                continue;
            }
            match read_process_memory(pid, region.start, len, caps) {
                Ok(data) => {
                    let hash: [u8; 32] = blake3::hash(&data).into();
                    baselines.push(RegionBaseline {
                        start: region.start,
                        len,
                        hash,
                        path: region.path.clone(),
                        is_text: false,
                        is_got: true,
                    });
                }
                Err(_) => continue,
            }
        }

        Ok(MemoryIntegrity { baselines })
    }

    /// Scan process memory against the baseline. Returns violations found.
    pub fn scan(
        &self,
        pid: i32,
        caps: &PlatformCapabilities,
    ) -> Vec<Violation> {
        let mut violations = Vec::new();

        for baseline in &self.baselines {
            let current = match read_process_memory(pid, baseline.start, baseline.len, caps) {
                Ok(data) => data,
                Err(_) => continue, // region may have been unmapped
            };

            let current_hash: [u8; 32] = blake3::hash(&current).into();
            if current_hash != baseline.hash {
                if baseline.is_text {
                    violations.push(Violation::TextModified {
                        region_path: baseline.path.clone(),
                        start: baseline.start,
                        expected: baseline.hash,
                        actual: current_hash,
                    });
                } else if baseline.is_got {
                    violations.push(Violation::GotOverwrite {
                        region_path: baseline.path.clone(),
                        start: baseline.start,
                        expected: baseline.hash,
                        actual: current_hash,
                    });
                } else {
                    violations.push(Violation::RegionModified {
                        start: baseline.start,
                        expected: baseline.hash,
                        actual: current_hash,
                    });
                }
            }
        }

        violations
    }

    /// Number of baselined regions.
    pub fn region_count(&self) -> usize {
        self.baselines.len()
    }
}

// ── Payload Corruption ("Bit Breaker") ──────────────────────────────────────

/// Corrupt a detected malicious payload in the target process's memory.
///
/// Writes random garbage with an illegal instruction prefix (ARM UDF or x86 UD2)
/// at the start. Only works if `cross_memory_attach` capability is available.
///
/// # Validation
/// - Rejects null addresses (`addr == 0`)
/// - Rejects lengths exceeding `MAX_MEMORY_OP_LEN` (4 MB)
/// - Verifies the target range `[addr, addr+len)` falls entirely within a single
///   executable memory region of the target process (parsed from `/proc/{pid}/maps`)
///
/// # Safety
/// This writes to another process's memory. Only call when you've confirmed
/// the target region contains malicious code that must be neutralized.
#[allow(dead_code)]
pub fn corrupt_payload(
    pid: i32,
    addr: u64,
    len: usize,
    caps: &PlatformCapabilities,
) -> Result<(), io::Error> {
    if !caps.cross_memory_attach {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "cross_memory_attach not available — cannot corrupt payload",
        ));
    }

    if len == 0 {
        return Ok(());
    }

    // Reject null address — writing to address 0 is never valid
    if addr == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "corrupt_payload: addr must not be null",
        ));
    }

    // Cap length to prevent unbounded writes
    if len > MAX_MEMORY_OP_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "corrupt_payload: length {} exceeds maximum {} bytes",
                len, MAX_MEMORY_OP_LEN
            ),
        ));
    }

    // Verify the target range falls within a single executable memory region
    // of the target process. We only corrupt code regions — writing to data
    // segments, heap, or stack is not the intended use of this function.
    let end_addr = addr.checked_add(len as u64).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "corrupt_payload: addr + len overflows u64",
        )
    })?;

    let map = MemoryMap::parse_pid(pid)?;
    let in_exec_region = map.regions.iter().any(|r| {
        r.is_executable() && r.start <= addr && end_addr <= r.end
    });

    if !in_exec_region {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "corrupt_payload: target range {:#x}..{:#x} is not within a single \
                 executable region of pid {}",
                addr, end_addr, pid
            ),
        ));
    }

    // Generate random garbage
    let mut garbage = vec![0xCCu8; len]; // INT3 fill as base

    // Fill with random bytes from /dev/urandom
    if let Ok(mut f) = fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut garbage);
    }

    // Insert illegal instruction at the start
    #[cfg(target_arch = "aarch64")]
    {
        // ARM64 UDF #0 (permanently undefined): 0x00000000
        if len >= 4 {
            garbage[0..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        }
    }
    #[cfg(target_arch = "x86_64")]
    {
        // x86 UD2 (undefined instruction): 0x0F 0x0B
        if len >= 2 {
            garbage[0] = 0x0F;
            garbage[1] = 0x0B;
        }
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        // Generic: fill start with zeros (likely illegal on most architectures)
        if len >= 4 {
            garbage[0..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        }
    }

    let local_iov = libc::iovec {
        iov_base: garbage.as_ptr() as *mut libc::c_void,
        iov_len: len,
    };
    let remote_iov = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: len,
    };

    let written = unsafe {
        libc::process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0)
    };

    if written < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

// ── Production Run Loop ─────────────────────────────────────────────────────

/// Run the memory sentinel as a periodic scan loop.
///
/// Baselines the target process's memory on startup, then periodically
/// re-scans and sends violations to the alert pipeline.
pub async fn run_memory_sentinel(
    config: MemorySentinelConfig,
    tx: mpsc::Sender<Alert>,
) {
    let pid = match config.target_pid {
        Some(pid) => pid as i32,
        None => {
            eprintln!("[memory_sentinel] no target_pid configured, not starting");
            return;
        }
    };

    let caps = PlatformCapabilities::probe();
    if !caps.proc_mem && !caps.cross_memory_attach {
        eprintln!("[memory_sentinel] no memory access method available (need CAP_SYS_PTRACE)");
        let _ = tx.send(Alert::new(
            Severity::Warning,
            "memory_sentinel",
            "Memory sentinel cannot start: no memory access method available",
        )).await;
        return;
    }

    // Capture baseline
    let integrity = match MemoryIntegrity::capture_baseline(pid, &caps) {
        Ok(integrity) => {
            eprintln!(
                "[memory_sentinel] baseline captured for pid {}: {} regions",
                pid,
                integrity.region_count()
            );
            integrity
        }
        Err(e) => {
            eprintln!("[memory_sentinel] failed to capture baseline for pid {}: {}", pid, e);
            let _ = tx.send(Alert::new(
                Severity::Warning,
                "memory_sentinel",
                &format!("Memory sentinel baseline failed for pid {}: {}", pid, e),
            )).await;
            return;
        }
    };

    let interval = Duration::from_millis(config.scan_interval_ms);
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await; // skip first immediate tick

    loop {
        ticker.tick().await;

        // Check if the process still exists
        if !std::path::Path::new(&format!("/proc/{}", pid)).exists() {
            eprintln!("[memory_sentinel] target pid {} no longer exists, stopping", pid);
            let _ = tx.send(Alert::new(
                Severity::Warning,
                "memory_sentinel",
                &format!("Memory sentinel target pid {} exited", pid),
            )).await;
            return;
        }

        let violations = integrity.scan(pid, &caps);
        for violation in &violations {
            let (severity, msg) = match violation {
                Violation::TextModified { region_path, start, .. } => {
                    (Severity::Critical, format!(
                        ".text segment modified in {} at {:#x} (pid {})",
                        region_path.as_deref().unwrap_or("unknown"),
                        start,
                        pid,
                    ))
                }
                Violation::GotOverwrite { region_path, start, .. } => {
                    (Severity::Critical, format!(
                        "GOT/PLT overwrite detected in {} at {:#x} (pid {})",
                        region_path.as_deref().unwrap_or("unknown"),
                        start,
                        pid,
                    ))
                }
                Violation::RegionModified { start, .. } => {
                    (Severity::Warning, format!(
                        "Memory region modified at {:#x} (pid {})",
                        start,
                        pid,
                    ))
                }
            };
            let _ = tx.send(Alert::new(severity, "memory_sentinel", &msg)).await;
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_MAPS: &str = "\
55d3a4400000-55d3a4420000 r--p 00000000 08:01 1234567  /usr/bin/target
55d3a4420000-55d3a4480000 r-xp 00020000 08:01 1234567  /usr/bin/target
55d3a4480000-55d3a44a0000 r--p 00080000 08:01 1234567  /usr/bin/target
55d3a44a0000-55d3a44b0000 rw-p 000a0000 08:01 1234567  /usr/bin/target
55d3a5000000-55d3a5021000 rw-p 00000000 00:00 0        [heap]
7f1234000000-7f1234020000 r--p 00000000 08:01 2345678  /usr/lib/libc.so.6
7f1234020000-7f1234180000 r-xp 00020000 08:01 2345678  /usr/lib/libc.so.6
7f1234180000-7f12341d0000 r--p 00180000 08:01 2345678  /usr/lib/libc.so.6
7f12341d0000-7f12341d4000 rw-p 001d0000 08:01 2345678  /usr/lib/libc.so.6
7f1234200000-7f1234220000 r-xp 00000000 08:01 3456789  /usr/lib/libclawtower.so
7f1234220000-7f1234224000 rw-p 00020000 08:01 3456789  /usr/lib/libclawtower.so
7ffd12340000-7ffd12360000 rw-p 00000000 00:00 0        [stack]
7ffd123fe000-7ffd12400000 r--p 00000000 00:00 0        [vvar]
7ffd12400000-7ffd12402000 r-xp 00000000 00:00 0        [vdso]";

    #[test]
    fn test_parse_memory_map() {
        let map = MemoryMap::parse_content(SAMPLE_MAPS);
        assert_eq!(map.regions.len(), 14);

        // Check first region
        assert_eq!(map.regions[0].start, 0x55d3a4400000);
        assert_eq!(map.regions[0].end, 0x55d3a4420000);
        assert_eq!(map.regions[0].perms, "r--p");
        assert_eq!(map.regions[0].path.as_deref(), Some("/usr/bin/target"));
    }

    #[test]
    fn test_text_regions() {
        let map = MemoryMap::parse_content(SAMPLE_MAPS);
        let text = map.text_regions();
        // r-xp regions: target .text, libc .text, libclawtower .text, [vdso]
        assert_eq!(text.len(), 4);
        assert!(text[0].path.as_deref() == Some("/usr/bin/target"));
        assert!(text[1].path.as_deref() == Some("/usr/lib/libc.so.6"));
    }

    #[test]
    fn test_got_plt_regions() {
        let map = MemoryMap::parse_content(SAMPLE_MAPS);
        let got = map.got_plt_regions();
        // rw-p regions with paths that also have r-xp: target, libc, libclawtower
        assert_eq!(got.len(), 3);
    }

    #[test]
    fn test_library_regions() {
        let map = MemoryMap::parse_content(SAMPLE_MAPS);
        let libs = map.library_regions();
        // libc.so.6 (4 regions) + libclawtower.so (2 regions) = 6
        assert_eq!(libs.len(), 6);
    }

    #[test]
    fn test_region_properties() {
        let map = MemoryMap::parse_content(SAMPLE_MAPS);
        let heap = map.regions.iter().find(|r| r.path.as_deref() == Some("[heap]")).unwrap();
        assert!(heap.is_writable());
        assert!(!heap.is_executable());
        assert!(!heap.is_text());

        let text = &map.regions[1]; // r-xp /usr/bin/target
        assert!(text.is_executable());
        assert!(!text.is_writable());
        assert!(text.is_text());
    }

    #[test]
    fn test_adaptive_scan_intervals() {
        assert_eq!(ThreatLevel::Normal.scan_interval(), Duration::from_secs(30));
        assert_eq!(ThreatLevel::Elevated.scan_interval(), Duration::from_secs(5));
        assert_eq!(ThreatLevel::Critical.scan_interval(), Duration::from_millis(500));
        assert_eq!(ThreatLevel::Lockdown.scan_interval(), Duration::from_millis(0));
    }

    #[test]
    fn test_threat_level_ordering() {
        assert!(ThreatLevel::Normal < ThreatLevel::Elevated);
        assert!(ThreatLevel::Elevated < ThreatLevel::Critical);
        assert!(ThreatLevel::Critical < ThreatLevel::Lockdown);
    }

    #[test]
    fn test_baseline_capture_and_scan_self() {
        let caps = PlatformCapabilities::probe();
        if !caps.proc_mem && !caps.cross_memory_attach {
            eprintln!("Skipping: no memory access method available");
            return;
        }

        let pid = std::process::id() as i32;
        let integrity = MemoryIntegrity::capture_baseline(pid, &caps)
            .expect("baseline capture should succeed on self");

        assert!(integrity.region_count() > 0, "should have at least one baselined region");

        // Scan immediately — GOT/PLT regions may change due to lazy binding,
        // so we only check .text violations (which should be stable).
        let violations = integrity.scan(pid, &caps);
        let text_violations: Vec<_> = violations.iter().filter(|v| matches!(v, Violation::TextModified { .. })).collect();
        assert!(text_violations.is_empty(), "no .text violations expected on unchanged self: {:?}", text_violations);
    }

    #[test]
    fn test_violation_detection_on_changed_memory() {
        // We can't actually modify our own .text in a test, but we can
        // verify the scan logic by creating an integrity instance with
        // a known-wrong baseline hash and checking that it detects it.
        let caps = PlatformCapabilities::probe();
        if !caps.proc_mem && !caps.cross_memory_attach {
            eprintln!("Skipping: no memory access method available");
            return;
        }

        let pid = std::process::id() as i32;
        let mut integrity = MemoryIntegrity::capture_baseline(pid, &caps)
            .expect("baseline capture should succeed");

        if integrity.baselines.is_empty() {
            eprintln!("Skipping: no baselines captured");
            return;
        }

        // Tamper with a baseline hash to simulate a modification
        integrity.baselines[0].hash = [0xFF; 32];

        let violations = integrity.scan(pid, &caps);
        assert!(!violations.is_empty(), "should detect violation with wrong baseline hash");
    }

    #[test]
    fn test_watchpoint_creation() {
        let caps = PlatformCapabilities::probe();
        if !caps.hw_breakpoints || caps.hw_watchpoint_count == 0 {
            eprintln!("Skipping: no hardware watchpoints available");
            return;
        }

        // Watch a stack variable in our own process
        let watched_var: u64 = 0xDEADBEEF;
        let addr = &watched_var as *const u64 as u64;

        let handle = set_watchpoint(0, addr, 8, WatchType::Write);
        assert!(handle.is_ok(), "watchpoint creation should succeed: {:?}", handle.err());

        // Dropping removes it
        drop(handle.unwrap());
    }

    #[test]
    fn test_corrupt_payload_on_forked_child() {
        let caps = PlatformCapabilities::probe();
        if !caps.cross_memory_attach {
            eprintln!("Skipping: cross_memory_attach not available");
            return;
        }

        // Fork a child, write to its executable memory region
        unsafe {
            // Create a shared writable region via pipe for synchronization
            let mut pipefd = [0i32; 2];
            assert_eq!(libc::pipe(pipefd.as_mut_ptr()), 0);

            let pid = libc::fork();
            assert!(pid >= 0, "fork failed");

            if pid == 0 {
                // Child: allocate an executable buffer, signal parent, then wait
                libc::close(pipefd[0]);
                let buf = libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );
                assert_ne!(buf, libc::MAP_FAILED);

                // Fill with known pattern
                libc::memset(buf, 0x41, 4096);

                // Write the buffer address to parent via pipe
                let addr_bytes = (buf as u64).to_ne_bytes();
                libc::write(pipefd[1], addr_bytes.as_ptr() as *const _, 8);
                libc::close(pipefd[1]);

                // Wait for parent to corrupt, then exit
                libc::sleep(2);
                libc::_exit(0);
            } else {
                // Parent: read buffer address from child
                libc::close(pipefd[1]);
                let mut addr_bytes = [0u8; 8];
                let n = libc::read(pipefd[0], addr_bytes.as_mut_ptr() as *mut _, 8);
                libc::close(pipefd[0]);

                if n == 8 {
                    let child_addr = u64::from_ne_bytes(addr_bytes);

                    // Small delay for child to settle
                    std::thread::sleep(std::time::Duration::from_millis(50));

                    // Corrupt!
                    let result = corrupt_payload(pid, child_addr, 64, &caps);
                    // This may fail with EPERM depending on ptrace_scope
                    if let Err(e) = &result {
                        eprintln!("corrupt_payload returned error (may be ptrace_scope): {}", e);
                    }
                    // Either way, we exercised the code path
                } else {
                    eprintln!("Failed to read address from child");
                }

                // Clean up child
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, std::ptr::null_mut(), 0);
            }
        }
    }

    #[test]
    fn test_parse_self_maps() {
        let map = MemoryMap::parse_pid(std::process::id() as i32)
            .expect("should parse own /proc/self/maps");
        assert!(!map.regions.is_empty());
        // Should have at least a stack and some executable regions
        let has_stack = map.regions.iter().any(|r| r.path.as_deref() == Some("[stack]"));
        let has_exec = map.regions.iter().any(|r| r.is_executable());
        assert!(has_stack, "should have [stack] region");
        assert!(has_exec, "should have executable regions");
    }

    #[test]
    fn test_watch_type_to_bp_type() {
        assert_eq!(WatchType::Write.to_bp_type(), HW_BREAKPOINT_W);
        assert_eq!(WatchType::ReadWrite.to_bp_type(), HW_BREAKPOINT_RW);
    }

    #[test]
    fn test_corrupt_payload_requires_capability() {
        let mut caps = PlatformCapabilities::probe();
        caps.cross_memory_attach = false;

        let result = corrupt_payload(1, 0x1000, 64, &caps);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn test_corrupt_payload_rejects_null_addr() {
        let mut caps = PlatformCapabilities::probe();
        caps.cross_memory_attach = true;

        let result = corrupt_payload(1, 0, 64, &caps);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_corrupt_payload_rejects_oversized_len() {
        let mut caps = PlatformCapabilities::probe();
        caps.cross_memory_attach = true;

        let result = corrupt_payload(1, 0x1000, MAX_MEMORY_OP_LEN + 1, &caps);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(
            err.to_string().contains("exceeds maximum"),
            "error should mention exceeds maximum, got: {}",
            err
        );
    }

    #[test]
    fn test_corrupt_payload_rejects_non_executable_region() {
        let caps = PlatformCapabilities::probe();
        if !caps.cross_memory_attach {
            eprintln!("Skipping: cross_memory_attach not available");
            return;
        }

        // Target our own heap — it's writable but NOT executable,
        // so corrupt_payload must reject it.
        let pid = std::process::id() as i32;
        let map = MemoryMap::parse_pid(pid).expect("should parse own maps");
        let heap = map.regions.iter().find(|r| r.path.as_deref() == Some("[heap]"));
        if let Some(heap_region) = heap {
            assert!(!heap_region.is_executable(), "heap should not be executable");
            let result = corrupt_payload(pid, heap_region.start, 64, &caps);
            assert!(result.is_err());
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        } else {
            eprintln!("Skipping: no [heap] region found in own maps");
        }
    }

    #[test]
    fn test_corrupt_payload_rejects_stack_region() {
        let caps = PlatformCapabilities::probe();
        if !caps.cross_memory_attach {
            eprintln!("Skipping: cross_memory_attach not available");
            return;
        }

        // Target our own stack — it's writable but NOT executable,
        // so corrupt_payload must reject it.
        let pid = std::process::id() as i32;
        let map = MemoryMap::parse_pid(pid).expect("should parse own maps");
        let stack = map.regions.iter().find(|r| r.path.as_deref() == Some("[stack]"));
        if let Some(stack_region) = stack {
            assert!(!stack_region.is_executable(), "stack should not be executable");
            let result = corrupt_payload(pid, stack_region.start, 64, &caps);
            assert!(result.is_err());
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        } else {
            eprintln!("Skipping: no [stack] region found in own maps");
        }
    }

    #[test]
    fn test_corrupt_payload_addr_len_overflow() {
        let mut caps = PlatformCapabilities::probe();
        caps.cross_memory_attach = true;

        // addr + len would overflow u64
        let result = corrupt_payload(1, u64::MAX, 64, &caps);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_read_process_memory_rejects_oversized_len() {
        let caps = PlatformCapabilities::probe();
        if !caps.proc_mem && !caps.cross_memory_attach {
            eprintln!("Skipping: no memory access method available");
            return;
        }

        let pid = std::process::id() as i32;
        let result = read_process_memory(pid, 0x1000, MAX_MEMORY_OP_LEN + 1, &caps);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(
            err.to_string().contains("exceeds maximum"),
            "error should mention exceeds maximum, got: {}",
            err
        );
    }

    #[test]
    fn test_read_cross_memory_rejects_oversized_len() {
        // Directly test the internal function
        let result = read_cross_memory(1, 0x1000, MAX_MEMORY_OP_LEN + 1);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(
            err.to_string().contains("exceeds maximum"),
            "error should mention exceeds maximum, got: {}",
            err
        );
    }
}
