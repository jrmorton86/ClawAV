// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Lightweight performance benchmarks (no external dependencies).

#[cfg(test)]
mod tests {
    use crate::enforcement::capabilities::PlatformCapabilities;
    use crate::detect::correlator::*;
    use crate::detect::forensics;
    use crate::sources::memory_sentinel::MemoryMap;
    use std::time::Instant;

    // ── 3a: Correlator throughput ───────────────────────────────────────

    #[test]
    fn bench_correlator_throughput() {
        let now = Instant::now();
        let mut c = Correlator::new(now);
        let n = 10_000;

        let start = Instant::now();
        for i in 0..n {
            c.ingest(Event {
                timestamp: now + std::time::Duration::from_micros(i),
                source: EventSource::LdPreload,
                kind: EventKind::OpenFile,
                pid: 1,
                detail: String::new(),
                threat_contribution: 0.0, // zero to avoid overflow
            });
        }
        let elapsed = start.elapsed();
        let events_per_sec = n as f64 / elapsed.as_secs_f64();

        eprintln!(
            "[bench] Correlator throughput: {} events in {:.2}ms = {:.0} events/sec (target: >100K)",
            n,
            elapsed.as_secs_f64() * 1000.0,
            events_per_sec
        );

        assert!(
            events_per_sec > 100_000.0,
            "Correlator throughput {:.0} events/sec below 100K target",
            events_per_sec
        );
    }

    // ── 3b: Capability probe time ───────────────────────────────────────

    #[test]
    fn bench_capability_probe_time() {
        let start = Instant::now();
        let _caps = PlatformCapabilities::probe();
        let elapsed = start.elapsed();

        eprintln!(
            "[bench] PlatformCapabilities::probe(): {:.2}ms (target: <100ms)",
            elapsed.as_secs_f64() * 1000.0
        );

        assert!(
            elapsed.as_millis() < 100,
            "Capability probe took {}ms, exceeds 100ms target",
            elapsed.as_millis()
        );
    }

    // ── 3c: Forensic dump time ──────────────────────────────────────────

    #[test]
    fn bench_forensic_dump_time() {
        let pid = std::process::id();
        let start = Instant::now();
        let _dump = forensics::capture_dump(pid, 0.0, "NORMAL", "benchmark").unwrap();
        let elapsed = start.elapsed();

        eprintln!(
            "[bench] capture_dump(self): {:.2}ms",
            elapsed.as_secs_f64() * 1000.0
        );
    }

    // ── 3d: Memory map parsing ──────────────────────────────────────────

    #[test]
    fn bench_memory_map_parsing() {
        let pid = std::process::id() as i32;
        let start = Instant::now();
        let _map = MemoryMap::parse_pid(pid).unwrap();
        let elapsed = start.elapsed();

        eprintln!(
            "[bench] MemoryMap::parse_pid(self): {:.2}ms (target: <10ms)",
            elapsed.as_secs_f64() * 1000.0
        );

        assert!(
            elapsed.as_millis() < 10,
            "Memory map parsing took {}ms, exceeds 10ms target",
            elapsed.as_millis()
        );
    }
}
