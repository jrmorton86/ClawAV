// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Integration tests exercising multiple modules together.

#[cfg(test)]
mod tests {
    use crate::enforcement::capabilities::PlatformCapabilities;
    use crate::detect::correlator::*;
    use crate::detect::forensics;
    use crate::sources::memory_sentinel::MemoryMap;
    use crate::enforcement::seccomp;
    use std::time::{Duration, Instant};

    fn make_event(source: EventSource, kind: EventKind, pid: u32, score: f64) -> Event {
        Event {
            timestamp: Instant::now(),
            source,
            kind,
            pid,
            detail: String::new(),
            threat_contribution: score,
        }
    }

    fn make_event_at(
        ts: Instant,
        source: EventSource,
        kind: EventKind,
        pid: u32,
        score: f64,
    ) -> Event {
        Event {
            timestamp: ts,
            source,
            kind,
            pid,
            detail: String::new(),
            threat_contribution: score,
        }
    }

    // ── 1a: Full pipeline test ──────────────────────────────────────────

    #[test]
    fn test_full_pipeline_attack_to_forensic_dump() {
        let now = Instant::now();
        let mut c = Correlator::new(now);

        // Simulate attack: sensitive read → connect → write
        c.ingest(make_event_at(
            now,
            EventSource::LdPreload,
            EventKind::ReadSensitive,
            1,
            200.0,
        ));
        c.ingest(make_event_at(
            now + Duration::from_secs(1),
            EventSource::Ebpf,
            EventKind::Connect,
            1,
            200.0,
        ));
        // ReadSensitive + Connect triggers cross-layer (+300), total so far: 200+200+300=700
        c.ingest(make_event_at(
            now + Duration::from_secs(2),
            EventSource::LdPreload,
            EventKind::WriteSocket,
            1,
            200.0,
        ));
        // WriteSocket after ReadSensitive triggers another cross-layer (+300), total: 1200

        assert!(
            matches!(c.state, ThreatState::Lockdown { .. }),
            "Expected Lockdown, got {:?} (score={:.0})",
            c.state.name(),
            c.threat_score
        );

        let actions = c.recommended_actions();
        assert!(actions.contains(&ActionKind::Freeze));
        assert!(actions.contains(&ActionKind::ForensicDump));

        // Capture forensic dump on self
        let pid = std::process::id();
        let dump = forensics::capture_dump(pid, c.threat_score, c.state.name(), "integration test")
            .expect("capture_dump should succeed");

        // Verify JSON roundtrip
        let json = serde_json::to_string_pretty(&dump).unwrap();
        let restored: forensics::ForensicDump = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.pid, pid);
        assert!(restored.threat_score >= 900.0);
        assert_eq!(restored.threat_state, "Lockdown");
        assert!(restored.memory_maps.is_some());
        assert!(restored.cmdline.is_some());
        assert!(!restored.trigger_pattern.is_empty());
    }

    // ── 1b: Capability-driven test ──────────────────────────────────────

    #[test]
    fn test_capability_driven() {
        let caps = PlatformCapabilities::probe();

        let score = caps.security_score();
        assert!(score >= 19 && score <= 100, "score {} out of range", score);

        let report = caps.report();
        assert!(report.contains("LAYER 1"));
        assert!(report.contains("LAYER 2"));
        assert!(report.contains("LAYER 3"));
        assert!(report.contains("LAYER 4"));

        // On this machine, minimum viable should pass (we have seccomp + proc_mem)
        assert!(
            caps.check_minimum_viable().is_ok(),
            "check_minimum_viable failed: {:?}",
            caps.check_minimum_viable()
        );
    }

    // ── 1c: Memory sentinel + correlator ────────────────────────────────

    #[test]
    fn test_memory_sentinel_plus_correlator() {
        let caps = PlatformCapabilities::probe();
        if !caps.proc_mem && !caps.cross_memory_attach {
            eprintln!("Skipping: no memory access method");
            return;
        }

        let pid = std::process::id() as i32;
        let _map = MemoryMap::parse_pid(pid).expect("should parse own maps");

        let now = Instant::now();
        let mut c = Correlator::new(now);

        // Ingest a MemoryViolation event
        c.ingest(make_event(
            EventSource::MemorySentinel,
            EventKind::MemoryViolation,
            pid as u32,
            500.0,
        ));

        assert!(
            matches!(c.state, ThreatState::Elevated { .. } | ThreatState::Critical { .. }),
            "Expected escalation, got {:?} (score={:.0})",
            c.state.name(),
            c.threat_score
        );
    }

    // ── 1d: Process cage + forensics ────────────────────────────────────

    #[test]
    fn test_process_cage_plus_forensics() {
        unsafe {
            let child_pid = libc::fork();
            assert!(child_pid >= 0, "fork failed");

            if child_pid == 0 {
                // Child: sleep forever
                loop {
                    libc::pause();
                }
            }

            // Emergency stop via SIGSTOP
            assert_eq!(libc::kill(child_pid, libc::SIGSTOP), 0);

            let mut status: i32 = 0;
            libc::waitpid(child_pid, &mut status, libc::WUNTRACED);
            assert!(libc::WIFSTOPPED(status), "child should be stopped");

            // Capture forensic dump of the stopped child
            let dump = forensics::capture_dump(
                child_pid as u32,
                800.0,
                "CRITICAL",
                "process_cage_test",
            )
            .expect("capture_dump on child should succeed");

            assert_eq!(dump.pid, child_pid as u32);
            assert_eq!(dump.threat_state, "CRITICAL");

            // Verify JSON validity
            let json = serde_json::to_string(&dump).unwrap();
            assert!(!json.is_empty());

            // Clean up
            libc::kill(child_pid, libc::SIGKILL);
            libc::waitpid(child_pid, &mut status, 0);
        }
    }

    // ── 1e: Seccomp + capabilities ──────────────────────────────────────

    #[test]
    fn test_seccomp_plus_capabilities() {
        let filter = seccomp::build_filter();
        let table = seccomp::syscall_table();

        // Filter should build successfully with reasonable instruction count
        let count = filter.len();
        assert!(
            count >= 20 && count <= 50,
            "Filter instruction count {} not in range 20-50",
            count
        );

        // Verify arch-specific syscall numbers are populated
        assert_eq!(table.kill_list.len(), 16);
        assert_eq!(table.trace_list.len(), 12);

        // All syscall numbers should be > 0
        for &nr in table.kill_list {
            assert!(nr > 0, "kill_list contains zero syscall number");
        }
        for &nr in table.trace_list {
            assert!(nr > 0, "trace_list contains zero syscall number");
        }
    }
}
