// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Adversarial tests simulating attack patterns and verifying detection.

#[cfg(test)]
mod tests {
    use crate::detect::correlator::*;
    use std::time::{Duration, Instant};

    fn make_event_at(
        ts: Instant,
        source: EventSource,
        kind: EventKind,
        pid: u32,
        score: f64,
        detail: &str,
    ) -> Event {
        Event {
            timestamp: ts,
            source,
            kind,
            pid,
            detail: detail.to_string(),
            threat_contribution: score,
        }
    }

    // ── 2a: Data exfiltration ───────────────────────────────────────────

    #[test]
    fn test_data_exfiltration_pattern() {
        let now = Instant::now();
        let mut c = Correlator::new(now);

        // open(/etc/shadow) → read(sensitive_fd) → connect(external_ip) → write(socket)
        c.ingest(make_event_at(now, EventSource::LdPreload, EventKind::OpenFile, 1, 100.0, "/etc/shadow"));
        c.ingest(make_event_at(now + Duration::from_millis(100), EventSource::LdPreload, EventKind::ReadSensitive, 1, 200.0, "fd=3"));
        c.ingest(make_event_at(now + Duration::from_millis(200), EventSource::Ebpf, EventKind::Connect, 1, 200.0, "203.0.113.1:443"));
        // ReadSensitive + Connect = +300 cross-layer. Total so far: 100+200+200+300=800
        c.ingest(make_event_at(now + Duration::from_millis(300), EventSource::LdPreload, EventKind::WriteSocket, 1, 200.0, "socket_fd=4"));
        // WriteSocket after ReadSensitive = +300. Total: 1300

        assert!(
            matches!(c.state, ThreatState::Lockdown { .. }),
            "Expected LOCKDOWN, got {:?} (score={:.0})",
            c.state.name(),
            c.threat_score
        );
    }

    // ── 2b: Shellcode injection ─────────────────────────────────────────

    #[test]
    fn test_shellcode_injection_pattern() {
        let now = Instant::now();
        let mut c = Correlator::new(now);

        // mmap(RW) → mprotect(PROT_EXEC)
        c.ingest(make_event_at(now, EventSource::Ebpf, EventKind::OpenFile, 1, 100.0, "mmap RW"));
        c.ingest(make_event_at(now + Duration::from_millis(50), EventSource::Seccomp, EventKind::Mprotect, 1, 500.0, "PROT_EXEC"));
        // Add memory violation for the injection
        c.ingest(make_event_at(now + Duration::from_millis(100), EventSource::MemorySentinel, EventKind::MemoryViolation, 1, 400.0, "W^X violation"));

        assert!(
            c.threat_score >= 900.0,
            "Expected score >= 900, got {:.0}",
            c.threat_score
        );
        assert!(
            matches!(c.state, ThreatState::Lockdown { .. }),
            "Expected LOCKDOWN, got {:?}",
            c.state.name()
        );
    }

    // ── 2c: Credential theft ────────────────────────────────────────────

    #[test]
    fn test_credential_theft_pattern() {
        let now = Instant::now();
        let mut c = Correlator::new(now);

        // read(~/.ssh/id_rsa) → execve(curl)
        c.ingest(make_event_at(now, EventSource::LdPreload, EventKind::ReadSensitive, 1, 300.0, "~/.ssh/id_rsa"));
        // eBPF exec without LdPreload exec for same pid → cross-layer bypass (+400)
        c.ingest(make_event_at(now + Duration::from_secs(1), EventSource::Ebpf, EventKind::Execve, 1, 200.0, "curl"));
        // Total: 300 + 200 + 400(cross-layer bypass) = 900+

        assert!(
            matches!(c.state, ThreatState::Lockdown { .. }),
            "Expected LOCKDOWN, got {:?} (score={:.0})",
            c.state.name(),
            c.threat_score
        );
    }

    // ── 2d: Static binary evasion ───────────────────────────────────────

    #[test]
    fn test_static_binary_evasion() {
        let now = Instant::now();
        let mut c = Correlator::new(now);

        // eBPF sees execve but NO LdPreload exec for this pid → cross-layer +400
        c.ingest(make_event_at(now, EventSource::Ebpf, EventKind::Execve, 42, 100.0, "/tmp/static_malware"));

        // 100 + 400 (cross-layer) = 500
        assert!(
            c.threat_score >= 500.0,
            "Expected >= 500 from cross-layer, got {:.0}",
            c.threat_score
        );
        assert!(
            matches!(c.state, ThreatState::Elevated { .. } | ThreatState::Critical { .. }),
            "Expected at least ELEVATED, got {:?}",
            c.state.name()
        );
    }

    // ── 2e: Directory enumeration ───────────────────────────────────────

    #[test]
    fn test_directory_enumeration() {
        let now = Instant::now();
        let mut c = Correlator::new(now);

        // 60 OpenFile events in under 1 second
        for i in 0..60 {
            c.ingest(make_event_at(
                now + Duration::from_millis(i * 15),
                EventSource::LdPreload,
                EventKind::OpenFile,
                1,
                6.0, // 6 * 60 = 360 total
                &format!("/etc/file_{}", i),
            ));
        }

        assert!(
            c.threat_score >= 300.0,
            "Expected >= 300 (ELEVATED), got {:.0}",
            c.threat_score
        );
        assert!(
            !matches!(c.state, ThreatState::Normal),
            "Should be at least ELEVATED, got Normal"
        );
    }

    // ── 2f: Slow drip attack ────────────────────────────────────────────

    #[test]
    fn test_slow_drip_attack_decays() {
        let now = Instant::now();
        let mut c = Correlator::new(now);

        // Ingest one mildly suspicious event every 30 seconds
        for i in 0..10 {
            let t = now + Duration::from_secs(i * 30);
            c.tick(t);
            let score_before = c.threat_score;
            c.ingest(make_event_at(t, EventSource::LdPreload, EventKind::OpenFile, 1, 100.0, "suspicious"));
            let _score_after = c.threat_score;

            // After first event, score should have decayed between events
            if i > 0 {
                // Decay over 30s at 50pts/s = 1500 pts. So previous score should be near 0
                // before the new 100 is added.
                assert!(
                    score_before < 100.0,
                    "Iteration {}: score_before={:.0} should have decayed",
                    i,
                    score_before
                );
            }
        }

        // Should NOT have accumulated to CRITICAL (600+)
        assert!(
            !matches!(c.state, ThreatState::Critical { .. } | ThreatState::Lockdown { .. }),
            "Slow drip should not reach CRITICAL, got {:?} (score={:.0})",
            c.state.name(),
            c.threat_score
        );
    }

    // ── 2g: False positive resilience ───────────────────────────────────

    #[test]
    fn test_false_positive_resilience() {
        let now = Instant::now();
        let mut c = Correlator::new(now);

        // Normal operations with low threat contributions
        let normal_events = vec![
            (EventSource::LdPreload, EventKind::OpenFile, "config.toml"),
            (EventSource::LdPreload, EventKind::OpenFile, "/etc/resolv.conf"),
            (EventSource::LdPreload, EventKind::Execve, "/usr/bin/ls"),
            (EventSource::Ebpf, EventKind::Execve, "/usr/bin/ls"), // matching exec from both layers
            (EventSource::LdPreload, EventKind::Connect, "127.0.0.1:8080"),
            (EventSource::LdPreload, EventKind::OpenFile, "/tmp/output.log"),
        ];

        for (i, (source, kind, detail)) in normal_events.into_iter().enumerate() {
            c.ingest(make_event_at(
                now + Duration::from_millis(i as u64 * 100),
                source,
                kind,
                1,
                10.0, // low score for normal ops
                detail,
            ));
        }

        // Should stay Normal (6 * 10 = 60, well below 300 threshold)
        assert!(
            matches!(c.state, ThreatState::Normal),
            "Normal operations should stay NORMAL, got {:?} (score={:.0})",
            c.state.name(),
            c.threat_score
        );
    }
}
