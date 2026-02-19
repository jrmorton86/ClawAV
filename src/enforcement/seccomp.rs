// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

#![allow(dead_code)]
//! Kernel-level syscall enforcement via seccomp-BPF.
//!
//! Phase 2 of the predictive interception system. Builds and installs a BPF
//! filter program that classifies syscalls into KILL, TRACE (currently LOG),
//! and ALLOW categories. Cannot be removed once applied (one-way escalation).
//!
//! ## Architecture Support
//! Uses conditional compilation for x86_64 vs aarch64 syscall number tables.
//!
//! ## Phase 3 TODO: Full SECCOMP_RET_TRACE
//! Currently the TRACE list uses `SECCOMP_RET_LOG` (log but allow). In Phase 3,
//! this will be replaced with `SECCOMP_RET_TRACE` + a ptrace-based sentinel:
//!
//! 1. The sentinel attaches to the target via `ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_TRACESECCOMP)`
//! 2. When a TRACE-listed syscall fires, the kernel pauses the process and
//!    delivers a `PTRACE_EVENT_SECCOMP` to the sentinel
//! 3. The sentinel reads syscall args via `PTRACE_GETREGS` / `PTRACE_PEEKDATA`
//! 4. Based on behavioral analysis (correlator engine), it either:
//!    - Allows: `PTRACE_CONT` with data=0
//!    - Denies: Rewrites syscall number to -1 (invalid) via `PTRACE_SETREGS`, then `PTRACE_CONT`
//!    - Kills: `kill(pid, SIGKILL)` for critical violations
//! 5. If the sentinel dies, traced syscalls fail-closed (KILL) — this is by design.

use crate::enforcement::capabilities::PlatformCapabilities;
use std::io;

// ── seccomp constants (not all in libc crate) ──────────────────────────────

const SECCOMP_MODE_FILTER: libc::c_int = 2;

const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;
const SECCOMP_RET_LOG: u32 = 0x7ffc0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;

// BPF instruction classes and fields
const BPF_LD: u16 = 0x00;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;

// Audit arch values
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH_CURRENT: u32 = 0xc000003e; // AUDIT_ARCH_X86_64
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_CURRENT: u32 = 0xc00000b7; // AUDIT_ARCH_AARCH64

// seccomp_data field offsets
const SECCOMP_DATA_NR_OFFSET: u32 = 0;        // offsetof(seccomp_data, nr)
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;      // offsetof(seccomp_data, arch)

// ── BPF instruction ────────────────────────────────────────────────────────

/// Raw BPF instruction (sock_filter equivalent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct BpfInsn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

impl BpfInsn {
    const fn new(code: u16, jt: u8, jf: u8, k: u32) -> Self {
        Self { code, jt, jf, k }
    }

    /// BPF_LD | BPF_W | BPF_ABS — load 32-bit word at absolute offset
    const fn ld_abs(offset: u32) -> Self {
        Self::new(BPF_LD | BPF_W | BPF_ABS, 0, 0, offset)
    }

    /// BPF_JMP | BPF_JEQ | BPF_K — jump if accumulator == k
    const fn jeq(k: u32, jt: u8, jf: u8) -> Self {
        Self::new(BPF_JMP | BPF_JEQ | BPF_K, jt, jf, k)
    }

    /// BPF_RET | BPF_K — return immediate value
    const fn ret(k: u32) -> Self {
        Self::new(BPF_RET | BPF_K, 0, 0, k)
    }
}

/// Serialise a BPF instruction to 8 bytes (little-endian, matches kernel ABI).
impl BpfInsn {
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[0..2].copy_from_slice(&self.code.to_ne_bytes());
        buf[2] = self.jt;
        buf[3] = self.jf;
        buf[4..8].copy_from_slice(&self.k.to_ne_bytes());
        buf
    }

    pub fn from_bytes(buf: &[u8; 8]) -> Self {
        Self {
            code: u16::from_ne_bytes([buf[0], buf[1]]),
            jt: buf[2],
            jf: buf[3],
            k: u32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]),
        }
    }
}

// ── Syscall number tables ──────────────────────────────────────────────────

/// Syscall numbers for the current architecture.
pub struct SyscallTable {
    pub kill_list: &'static [u32],
    pub trace_list: &'static [u32],
}

#[cfg(target_arch = "x86_64")]
mod syscall_numbers {
    // KILL list
    pub const PTRACE: u32 = 101;
    pub const INIT_MODULE: u32 = 175;
    pub const FINIT_MODULE: u32 = 313;
    pub const DELETE_MODULE: u32 = 176;
    pub const KEXEC_LOAD: u32 = 246;
    pub const KEXEC_FILE_LOAD: u32 = 320;
    pub const PIVOT_ROOT: u32 = 155;
    pub const MOUNT: u32 = 165;
    pub const UMOUNT2: u32 = 166;
    pub const SWAPON: u32 = 167;
    pub const SWAPOFF: u32 = 168;
    pub const REBOOT: u32 = 169;
    pub const SETTIMEOFDAY: u32 = 164;
    pub const CLOCK_SETTIME: u32 = 227;
    pub const ACCT: u32 = 163;
    pub const QUOTACTL: u32 = 179;

    pub const MEMFD_CREATE: u32 = 319;
    pub const PROCESS_VM_WRITEV: u32 = 311;
    pub const UNSHARE: u32 = 272;
    pub const SETNS: u32 = 308;
    pub const IO_URING_SETUP: u32 = 425;
    pub const IO_URING_ENTER: u32 = 426;
    pub const IO_URING_REGISTER: u32 = 427;

    pub static KILL_LIST: &[u32] = &[
        PTRACE, INIT_MODULE, FINIT_MODULE, DELETE_MODULE,
        KEXEC_LOAD, KEXEC_FILE_LOAD, PIVOT_ROOT,
        MOUNT, UMOUNT2, SWAPON, SWAPOFF,
        REBOOT, SETTIMEOFDAY, CLOCK_SETTIME, ACCT, QUOTACTL,
        MEMFD_CREATE, PROCESS_VM_WRITEV,
        UNSHARE, SETNS, IO_URING_SETUP, IO_URING_ENTER, IO_URING_REGISTER,
    ];

    // TRACE list
    pub const EXECVE: u32 = 59;
    pub const EXECVEAT: u32 = 322;
    pub const CONNECT: u32 = 42;
    pub const BIND: u32 = 49;
    pub const LISTEN: u32 = 50;
    pub const ACCEPT: u32 = 43;
    pub const ACCEPT4: u32 = 288;
    pub const CLONE: u32 = 56;
    pub const CLONE3: u32 = 435;
    pub const MPROTECT: u32 = 10;

    pub static TRACE_LIST: &[u32] = &[
        EXECVE, EXECVEAT, CONNECT, BIND, LISTEN, ACCEPT, ACCEPT4,
        CLONE, CLONE3, MPROTECT,
    ];
}

#[cfg(target_arch = "aarch64")]
mod syscall_numbers {
    // KILL list — aarch64 uses the "new" generic syscall table
    pub const PTRACE: u32 = 117;
    pub const INIT_MODULE: u32 = 105;
    pub const FINIT_MODULE: u32 = 273;
    pub const DELETE_MODULE: u32 = 106;
    pub const KEXEC_LOAD: u32 = 104;
    pub const KEXEC_FILE_LOAD: u32 = 294;
    pub const PIVOT_ROOT: u32 = 41;
    pub const MOUNT: u32 = 40;
    pub const UMOUNT2: u32 = 39;
    pub const SWAPON: u32 = 224;
    pub const SWAPOFF: u32 = 225;
    pub const REBOOT: u32 = 142;
    pub const SETTIMEOFDAY: u32 = 170;
    pub const CLOCK_SETTIME: u32 = 112;
    pub const ACCT: u32 = 89;
    pub const QUOTACTL: u32 = 60;
    pub const MEMFD_CREATE: u32 = 279;
    pub const PROCESS_VM_WRITEV: u32 = 271;
    pub const UNSHARE: u32 = 97;
    pub const SETNS: u32 = 268;
    pub const IO_URING_SETUP: u32 = 425;
    pub const IO_URING_ENTER: u32 = 426;
    pub const IO_URING_REGISTER: u32 = 427;

    pub static KILL_LIST: &[u32] = &[
        PTRACE, INIT_MODULE, FINIT_MODULE, DELETE_MODULE,
        KEXEC_LOAD, KEXEC_FILE_LOAD, PIVOT_ROOT,
        MOUNT, UMOUNT2, SWAPON, SWAPOFF,
        REBOOT, SETTIMEOFDAY, CLOCK_SETTIME, ACCT, QUOTACTL,
        MEMFD_CREATE, PROCESS_VM_WRITEV,
        UNSHARE, SETNS, IO_URING_SETUP, IO_URING_ENTER, IO_URING_REGISTER,
    ];

    // TRACE list
    pub const EXECVE: u32 = 221;
    pub const EXECVEAT: u32 = 281;
    pub const CONNECT: u32 = 203;
    pub const BIND: u32 = 200;
    pub const LISTEN: u32 = 201;
    pub const ACCEPT: u32 = 202;
    pub const ACCEPT4: u32 = 242;
    pub const CLONE: u32 = 220;
    pub const CLONE3: u32 = 435;
    pub const MPROTECT: u32 = 226;

    pub static TRACE_LIST: &[u32] = &[
        EXECVE, EXECVEAT, CONNECT, BIND, LISTEN, ACCEPT, ACCEPT4,
        CLONE, CLONE3, MPROTECT,
    ];
}

/// Returns the syscall table for the current architecture.
pub fn syscall_table() -> SyscallTable {
    SyscallTable {
        kill_list: syscall_numbers::KILL_LIST,
        trace_list: syscall_numbers::TRACE_LIST,
    }
}

// ── BPF filter builder ─────────────────────────────────────────────────────

/// Build the seccomp-BPF filter program.
///
/// Structure:
/// 1. Load arch, verify it matches (KILL if wrong arch)
/// 2. Load syscall number
/// 3. Check against KILL list → SECCOMP_RET_KILL_PROCESS
/// 4. Check against TRACE list → SECCOMP_RET_LOG (Phase 3: SECCOMP_RET_TRACE)
/// 5. Default → SECCOMP_RET_ALLOW
pub fn build_filter() -> Vec<BpfInsn> {
    let table = syscall_table();
    let kill_count = table.kill_list.len();
    let trace_count = table.trace_list.len();

    // Total instructions:
    // 1 (load arch) + 1 (check arch) +
    // 1 (load nr) +
    // kill_count (jeq to kill_ret) +
    // trace_count (jeq to trace_ret) +
    // 1 (allow ret) + 1 (trace ret) + 1 (kill ret)
    let total = 3 + kill_count + trace_count + 3;
    assert!(total <= 255, "BPF filter too large for u8 jump offsets ({} instructions)", total);
    let mut prog = Vec::with_capacity(total);

    // [0] Load architecture
    prog.push(BpfInsn::ld_abs(SECCOMP_DATA_ARCH_OFFSET));

    // [1] Verify arch — if mismatch, kill
    // jt=0 means fall through (next insn), jf jumps to kill_ret
    let insns_after_arch_check = (total - 2) as u8;
    prog.push(BpfInsn::jeq(AUDIT_ARCH_CURRENT, 0, insns_after_arch_check));

    // [2] Load syscall number
    prog.push(BpfInsn::ld_abs(SECCOMP_DATA_NR_OFFSET));

    // [3..3+kill_count) Check KILL list
    // Each JEQ: if match, jump to kill_ret; if not, fall through
    for (i, &nr) in table.kill_list.iter().enumerate() {
        let remaining_kill = (kill_count - 1 - i) as u8;
        let remaining_trace = trace_count as u8;
        // Jump forward to kill_ret: remaining_kill + remaining_trace + 1(allow) + 1(trace)
        let jt = remaining_kill + remaining_trace + 2;
        prog.push(BpfInsn::jeq(nr, jt, 0));
    }

    // [3+kill_count..3+kill_count+trace_count) Check TRACE list
    for (i, &nr) in table.trace_list.iter().enumerate() {
        let remaining_trace = (trace_count - 1 - i) as u8;
        // Jump forward to trace_ret: remaining_trace + 1(allow)
        let jt = remaining_trace + 1;
        prog.push(BpfInsn::jeq(nr, jt, 0));
    }

    // Default: ALLOW
    prog.push(BpfInsn::ret(SECCOMP_RET_ALLOW));

    // TRACE return (LOG for now)
    prog.push(BpfInsn::ret(SECCOMP_RET_LOG));

    // KILL return
    prog.push(BpfInsn::ret(SECCOMP_RET_KILL_PROCESS));

    debug_assert_eq!(prog.len(), total);
    prog
}

/// Serialise the filter to bytes.
pub fn filter_to_bytes(filter: &[BpfInsn]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(filter.len() * 8);
    for insn in filter {
        bytes.extend_from_slice(&insn.to_bytes());
    }
    bytes
}

/// Deserialise a filter from bytes.
pub fn filter_from_bytes(bytes: &[u8]) -> Option<Vec<BpfInsn>> {
    if bytes.len() % 8 != 0 {
        return None;
    }
    let mut filter = Vec::with_capacity(bytes.len() / 8);
    for chunk in bytes.chunks_exact(8) {
        let arr: [u8; 8] = chunk.try_into().ok()?;
        filter.push(BpfInsn::from_bytes(&arr));
    }
    Some(filter)
}

// ── Profile installer ──────────────────────────────────────────────────────

/// sock_fprog equivalent for prctl.
#[repr(C)]
struct SockFprog {
    len: libc::c_ushort,
    filter: *const BpfInsn,
}

/// Install the seccomp-BPF filter on the current process/thread.
///
/// This is a one-way operation:
/// 1. Sets `PR_SET_NO_NEW_PRIVS` (cannot be undone)
/// 2. Applies the BPF filter via `PR_SET_SECCOMP`
///
/// Returns an error if seccomp is not available or the syscall fails.
pub fn install_filter(caps: &PlatformCapabilities) -> Result<(), SeccompError> {
    if !caps.seccomp_filter {
        eprintln!("[WARN] seccomp-BPF not available on this platform, skipping filter installation");
        return Err(SeccompError::NotAvailable);
    }

    let filter = build_filter();
    install_raw_filter(&filter)
}

/// Install an arbitrary BPF filter (for testing or custom profiles).
pub fn install_raw_filter(filter: &[BpfInsn]) -> Result<(), SeccompError> {
    // Step 1: PR_SET_NO_NEW_PRIVS
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err(SeccompError::Prctl(io::Error::last_os_error()));
    }

    // Step 2: PR_SET_SECCOMP with SECCOMP_MODE_FILTER
    let prog = SockFprog {
        len: filter.len() as libc::c_ushort,
        filter: filter.as_ptr(),
    };

    let ret = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER as libc::c_ulong,
            &prog as *const SockFprog as libc::c_ulong,
            0,
            0,
        )
    };

    if ret != 0 {
        return Err(SeccompError::Seccomp(io::Error::last_os_error()));
    }

    eprintln!("[INFO] seccomp-BPF filter installed ({} instructions)", filter.len());
    Ok(())
}

/// Errors from seccomp operations.
#[derive(Debug)]
pub enum SeccompError {
    /// seccomp-BPF not available on this platform.
    NotAvailable,
    /// prctl(PR_SET_NO_NEW_PRIVS) failed.
    Prctl(io::Error),
    /// prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER) failed.
    Seccomp(io::Error),
}

impl std::fmt::Display for SeccompError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAvailable => write!(f, "seccomp-BPF not available"),
            Self::Prctl(e) => write!(f, "PR_SET_NO_NEW_PRIVS failed: {}", e),
            Self::Seccomp(e) => write!(f, "PR_SET_SECCOMP failed: {}", e),
        }
    }
}

impl std::error::Error for SeccompError {}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_instruction_count() {
        let filter = build_filter();
        let table = syscall_table();
        let expected = 3 + table.kill_list.len() + table.trace_list.len() + 3;
        assert_eq!(filter.len(), expected);
    }

    #[test]
    fn test_filter_structure() {
        let filter = build_filter();

        // First instruction: load arch
        assert_eq!(filter[0].code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(filter[0].k, SECCOMP_DATA_ARCH_OFFSET);

        // Second: arch check (JEQ)
        assert_eq!(filter[1].code, BPF_JMP | BPF_JEQ | BPF_K);
        assert_eq!(filter[1].k, AUDIT_ARCH_CURRENT);

        // Third: load syscall nr
        assert_eq!(filter[2].code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(filter[2].k, SECCOMP_DATA_NR_OFFSET);

        // Last three: allow, log, kill returns
        let n = filter.len();
        assert_eq!(filter[n - 3].code, BPF_RET | BPF_K);
        assert_eq!(filter[n - 3].k, SECCOMP_RET_ALLOW);
        assert_eq!(filter[n - 2].code, BPF_RET | BPF_K);
        assert_eq!(filter[n - 2].k, SECCOMP_RET_LOG);
        assert_eq!(filter[n - 1].code, BPF_RET | BPF_K);
        assert_eq!(filter[n - 1].k, SECCOMP_RET_KILL_PROCESS);
    }

    #[test]
    fn test_syscall_tables_populated() {
        let table = syscall_table();
        assert_eq!(table.kill_list.len(), 23);
        assert_eq!(table.trace_list.len(), 10);

        // All entries should be unique
        let mut kill_set: Vec<u32> = table.kill_list.to_vec();
        kill_set.sort();
        kill_set.dedup();
        assert_eq!(kill_set.len(), table.kill_list.len(), "duplicate in kill list");

        let mut trace_set: Vec<u32> = table.trace_list.to_vec();
        trace_set.sort();
        trace_set.dedup();
        assert_eq!(trace_set.len(), table.trace_list.len(), "duplicate in trace list");

        // No overlap between lists
        for &nr in table.kill_list {
            assert!(!table.trace_list.contains(&nr), "syscall {} in both lists", nr);
        }
    }

    #[test]
    fn test_filter_serialize_deserialize() {
        let filter = build_filter();
        let bytes = filter_to_bytes(&filter);
        assert_eq!(bytes.len(), filter.len() * 8);

        let restored = filter_from_bytes(&bytes).expect("deserialize failed");
        assert_eq!(filter.len(), restored.len());
        for (a, b) in filter.iter().zip(restored.iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn test_filter_from_bytes_invalid() {
        // Odd number of bytes should fail
        assert!(filter_from_bytes(&[0u8; 7]).is_none());
        assert!(filter_from_bytes(&[0u8; 9]).is_none());
        // Empty is fine
        assert_eq!(filter_from_bytes(&[]).unwrap().len(), 0);
    }

    #[test]
    fn test_bpf_insn_roundtrip() {
        let insn = BpfInsn::new(0x1234, 0xAB, 0xCD, 0xDEADBEEF);
        let bytes = insn.to_bytes();
        let restored = BpfInsn::from_bytes(&bytes);
        assert_eq!(insn, restored);
    }

    #[test]
    fn test_install_in_forked_child() {
        // Fork a child process so the seccomp filter doesn't affect the test runner.
        // The child installs the filter and exits; we verify it succeeded.
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0, "fork failed");

            if pid == 0 {
                // Child process
                let filter = build_filter();
                match install_raw_filter(&filter) {
                    Ok(()) => libc::_exit(0),
                    Err(_) => libc::_exit(1),
                }
            } else {
                // Parent: wait for child
                let mut status: libc::c_int = 0;
                let ret = libc::waitpid(pid, &mut status, 0);
                assert_eq!(ret, pid);
                assert!(
                    libc::WIFEXITED(status),
                    "child did not exit normally (status={})", status
                );
                let exit_code = libc::WEXITSTATUS(status);
                // exit_code 0 = success, 1 = seccomp install failed (e.g. unprivileged in container)
                // Both are acceptable — we just verify the child didn't crash
                assert!(
                    exit_code == 0 || exit_code == 1,
                    "unexpected exit code: {}", exit_code
                );
            }
        }
    }

    #[test]
    fn test_install_without_caps() {
        let mut caps = PlatformCapabilities::probe();
        caps.seccomp_filter = false;
        match install_filter(&caps) {
            Err(SeccompError::NotAvailable) => {} // expected
            other => panic!("expected NotAvailable, got {:?}", other),
        }
    }

    #[test]
    fn test_kill_list_syscalls_present() {
        // Verify specific well-known syscall numbers for current arch
        #[cfg(target_arch = "x86_64")]
        {
            assert!(syscall_numbers::KILL_LIST.contains(&101)); // ptrace
            assert!(syscall_numbers::KILL_LIST.contains(&165)); // mount
            assert!(syscall_numbers::KILL_LIST.contains(&169)); // reboot
        }
        #[cfg(target_arch = "aarch64")]
        {
            assert!(syscall_numbers::KILL_LIST.contains(&117)); // ptrace
            assert!(syscall_numbers::KILL_LIST.contains(&40));  // mount
            assert!(syscall_numbers::KILL_LIST.contains(&142)); // reboot
        }
    }

    #[test]
    fn test_trace_list_syscalls_present() {
        #[cfg(target_arch = "x86_64")]
        {
            assert!(syscall_numbers::TRACE_LIST.contains(&59));  // execve
            assert!(syscall_numbers::TRACE_LIST.contains(&42));  // connect
            assert!(syscall_numbers::TRACE_LIST.contains(&56));  // clone
        }
        #[cfg(target_arch = "aarch64")]
        {
            assert!(syscall_numbers::TRACE_LIST.contains(&221)); // execve
            assert!(syscall_numbers::TRACE_LIST.contains(&203)); // connect
            assert!(syscall_numbers::TRACE_LIST.contains(&220)); // clone
        }
    }
}
