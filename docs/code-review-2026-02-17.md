# Code Review: Core Detection Modules — 2026-02-17

**Reviewer:** Automated deep review (Task 13)  
**Modules:** `behavior.rs`, `scanner.rs`, `policy.rs`  
**Version:** v0.3.2  
**Classification:** 🐛 Bug | 🔧 Improvement | 🎨 Style

---

## 1. `src/behavior.rs` (2562 lines)

### 1.1 Bugs

#### 🐛 B-1: History tamper bypass via `ln` (line ~480)
The history tampering check only fires for binaries `["rm", "mv", "cp", ">", "truncate", "unset", "export"]`. An attacker can bypass with:
```bash
ln -sf /dev/null ~/.bash_history
```
`ln` is not in the checked binary list, so this evades detection entirely.

**Fix:** Add `"ln"` to the history tamper binary check list.

#### 🐛 B-2: Binary replacement check requires `args.len() > 2` (line ~510)
```rust
if arg.starts_with(pattern) && args.len() > 2 {
```
This means `cp /usr/bin/ls` (with only 2 args) won't trigger. While unusual, `mv /usr/bin/ls` (rename to destroy) with exactly 2 args would be missed.

**Fix:** Change to `args.len() >= 2` — any write tool targeting a system binary path is suspicious.

#### 🐛 B-3: `rsync` in EXFIL_COMMANDS but only checked unconditionally (line ~101)
`rsync` is listed in `EXFIL_COMMANDS` and gets flagged for ANY invocation (even local `rsync -a dir1/ dir2/`). Unlike `scp`/`sftp` which check for `@`, rsync is unconditionally blocked. Local rsync is a common legitimate operation.

**Fix:** Move `rsync` to `REMOTE_TRANSFER_COMMANDS` (check for `@` in args), or add a local-path exemption.

#### 🐛 B-4: Scheduled task double-check (lines ~340 + ~558)
`PERSISTENCE_BINARIES` and `SCHEDULED_TASK_BINARIES` both contain `at`, `atq`, `atrm`, `batch`, `crontab`. The persistence check fires first (Critical) and returns early, so the scheduled task check (Warning, line ~558) is **dead code** for these binaries. The `crontab -l` skip in the scheduled task section is also unreachable.

**Fix:** Remove `SCHEDULED_TASK_BINARIES` or merge with `PERSISTENCE_BINARIES`. Keep the `-l` exemption in the persistence section (already present).

### 1.2 False Positive Risks

#### 🔧 B-5: `python3 -c` / `node -e` flags entire inline execution as Warning (line ~607)
Any use of `python3 -c "print('hello')"` triggers DataExfiltration Warning. This is extremely noisy for AI agents that commonly run inline Python/Node for calculations, JSON parsing, etc.

**Severity:** High false positive rate  
**Fix:** Only flag inline execution when combined with network-indicative strings (socket, http, connect, urllib, fetch, etc.). Current heuristic is too broad.

#### 🔧 B-6: `base64` unconditionally flagged as DataExfiltration Warning (line ~634)
`base64 /etc/hostname` or even `echo test | base64` triggers a warning. Base64 is commonly used for non-malicious encoding (CI/CD tokens, config generation).

**Fix:** Only flag when combined with piping to network tools or when used on sensitive files.

#### 🔧 B-7: `git push` flagged as DataExfiltration Warning (line ~625)
AI agents frequently push code. This will generate constant noise on any development machine.

**Fix:** Consider Info severity, or only flag when pushing to non-origin remotes or when the remote URL was recently changed.

#### 🔧 B-8: `env` / `printenv` as Reconnaissance Warning (line ~614)
Agents commonly run `env` to check their environment. This is standard operational behavior.

**Fix:** Downgrade to Info severity.

#### 🔧 B-9: `systemctl enable` any service is Warning (line ~348)
`systemctl enable nginx` or other legitimate services triggers Warning. Only truly suspicious when enabling unknown/new services.

**Fix:** Add an allowlist of common services (nginx, postgresql, redis, etc.) or only flag services in /tmp or user-created paths.

### 1.3 Missing Detection Patterns (MITRE ATT&CK gaps)

#### 🔧 B-10: No crypto miner detection (T1496 - Resource Hijacking)
Tests confirm `xmrig`, `minerd`, and stratum protocol URLs are not detected. These are high-confidence indicators.

**Fix:** Add `CRYPTO_MINER_PATTERNS` list: `["xmrig", "minerd", "cpuminer", "bfgminer", "stratum+tcp", "stratum+ssl", "cryptonight", "randomx"]`.

#### 🔧 B-11: No `chmod u+s` / SUID bit detection (T1548.001)
Setting SUID bit (`chmod u+s`, `chmod 4755`) is not detected in behavior.rs. Only the policy engine catches this.

**Fix:** Add explicit detection for `chmod` with SUID patterns.

#### 🔧 B-12: No `dd if=/dev/sda` detection (T1005 - Data from Local System)
Raw disk reading via `dd` is only checked for `/proc/kcore` and sensitive files, not block devices. Tests confirm `dd if=/dev/sda` is undetected.

**Fix:** Flag `dd` with `if=/dev/sd*` or `if=/dev/nvme*` patterns.

#### 🔧 B-13: No `getent` detection
`getent passwd`, `getent shadow` enumeration is not caught. `getent` is not in RECON_COMMANDS.

**Fix:** Add `getent` to RECON_COMMANDS, flag `getent shadow` as Critical (equivalent to reading /etc/shadow).

#### 🔧 B-14: No `ip route add` / network manipulation detection (T1599)
`ip route add`, `ip rule add`, `arp -s` for ARP poisoning, routing table manipulation — none detected.

**Fix:** Add network manipulation patterns.

#### 🔧 B-15: No fileless execution detection (T1620)
`memfd_create` syscall (used for fileless execution) is not monitored. Also `python3 -c "exec(compile(...))"` and `/proc/self/fd/` execution.

**Fix:** Add `memfd_create` to monitored syscalls.

### 1.4 Severity Level Issues

#### 🔧 B-16: `at` command is Critical but should be Warning
The `at` command for one-time scheduling is less dangerous than persistent crontab entries. `atq` (list) and `atrm` (remove) are read/cleanup operations flagged as Critical.

**Fix:** `atq` → None (read-only), `atrm` → Info (cleanup), `at`/`batch` → Warning.

#### 🔧 B-17: Inconsistent severity between behavior.rs and policy.rs
`systemctl enable` is Warning in behavior.rs but the policy's `detect-service-creation` also catches it. When both fire, the aggregator deduplicates but the logged severity may vary depending on which fires first.

---

## 2. `src/scanner.rs` (3014 lines)

### 2.1 Bugs

#### 🐛 S-1: `find -perm 0002` passed as single string (line ~194)
```rust
run_cmd("find", &[dir, "-type", "f", "-perm", "0002", "2>/dev/null"])
```
The `2>/dev/null` is passed as a literal argument to `find`, not interpreted by a shell. This means `find` receives a bogus argument and likely fails silently. The same issue applies to `scan_suid_sgid_binaries` (line ~213).

**Fix:** Use `run_cmd("bash", &["-c", "find ..."])` or remove the `2>/dev/null` (errors are already ignored via `Err(_) => {}`).

#### 🐛 S-2: `lsof` piped command doesn't work (line ~351)
```rust
run_cmd("lsof", &["-n", "|", "wc", "-l"])
```
`run_cmd` uses `Command::new`, which does NOT invoke a shell. The pipe `|` and `wc -l` are passed as literal arguments to `lsof`. This scan always fails.

**Fix:** Use `run_cmd("bash", &["-c", "lsof -n 2>/dev/null | wc -l"])`.

#### 🐛 S-3: Password policy flags legitimate locked accounts (line ~477)
```rust
if password_hash.is_empty() || password_hash == "*" || password_hash == "!" {
```
`!` and `*` in shadow mean the account is **locked** (no login). These are then checked for shell access, but locked accounts with `/bin/bash` are common for service accounts that use `su` or `sudo` (e.g., `root` itself on Ubuntu has `!` and `/bin/bash`). This will generate noise.

**Fix:** Skip accounts where hash starts with `!` or `*` — these are locked by definition.

#### 🐛 S-4: DNS resolver flags all non-RFC1918 servers as suspicious (line ~396)
The check flags any DNS server not in `127.*`, `192.168.*`, `10.*`, `172.*`, plus a hardcoded allowlist of only `8.8.4.4`, `8.8.8.8`, `1.1.1.1`, `1.0.0.1`. Cloud provider DNS (e.g., 169.254.169.253 AWS, systemd-resolved 127.0.0.53) and ISP DNS will all generate warnings.

**Fix:** Add `169.254.*` (link-local/cloud), and expand the known-good list, or invert the logic to flag only when DNS servers are in known-malicious ranges.

### 2.2 Permanent Noise (scans that never pass)

#### 🔧 S-5: `scan_ssh` warns if SSH is running
Most systems need SSH. Warning on every scan cycle creates permanent noise.

**Fix:** Make this configurable or only warn if SSH is bound to `0.0.0.0` (vs localhost-only).

#### 🔧 S-6: `scan_listening_services` only expects port 18791
Any system with other services (web server, database, etc.) will always fail. The expected ports list is too narrow.

**Fix:** Make the expected ports configurable via config.toml. At minimum add 22 (SSH), 53 (DNS).

#### 🔧 S-7: `scan_swap_tmpfs_security` flags `/tmp` not separately mounted
Most single-disk systems don't mount `/tmp` separately. This is permanent noise.

**Fix:** Downgrade from Warn to Info, or make it configurable.

#### 🔧 S-8: `scan_password_policy` flags `PASS_MAX_DAYS > 90`
The default on most distros is 99999. This will always warn.

**Fix:** Only flag if the system has interactive human users (skip for agent-only hosts).

#### 🔧 S-9: `scan_systemd_hardening` lists 8 hardening features, most missing by default
Unless the service file was manually hardened (many features like `MemoryDenyWriteExecute` break some workloads), this always warns.

**Fix:** Differentiate between recommended and required features. Only fail on critical ones.

#### 🔧 S-10: `scan_environment_variables` flags any env var containing KEY/SECRET/TOKEN with >20 chars
This will fire for `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, etc. — which are required for agent operation.

**Fix:** Add an allowlist of expected credential env vars, or move this check to the cognitive monitoring system.

### 2.3 Redundant Scans

#### 🔧 S-11: Crontab checked by both `scan_crontab_audit` and `scan_user_persistence`
Both scan crontabs. `scan_crontab_audit` checks system crontabs for suspicious patterns; `scan_user_persistence` checks user crontab existence. They can produce conflicting results (one PASS, one FAIL).

**Fix:** Consolidate into one crontab scan, or clearly separate concerns (system vs user).

#### 🔧 S-12: `scan_user_account_audit` and `scan_environment_variables` both check credentials
User account audit checks for credentials in `/proc/<pid>/environ`; environment variables scan checks the current process env. Overlap in credential detection.

### 2.4 Missing Scans

#### 🔧 S-13: No scan for recently modified binaries in PATH
Check for binaries in `/usr/bin`, `/usr/sbin` with mtime in last 24h (outside of package manager updates). Would catch trojanized binaries.

#### 🔧 S-14: No scan for hidden processes
Compare `ps aux` output vs `/proc/*/` enumeration. Discrepancy indicates a rootkit.

#### 🔧 S-15: No scan for open SSH tunnels
`ss -tlnp` is checked for listeners but not for established outbound tunnels (`ss -tnp state established`).

#### 🔧 S-16: No scan for writable directories in PATH
`PATH` directories writable by non-root allow binary planting attacks.

### 2.5 Style

#### 🎨 S-17: Blocking I/O in scan functions
All scan functions use `std::process::Command` (blocking). They're wrapped in `spawn_blocking` at the top level, which is correct, but individual scans could be parallelized with `tokio::task::JoinSet` for faster scan cycles.

---

## 3. `src/policy.rs` (1941 lines)

### 3.1 Bugs

#### 🐛 P-1: Malformed YAML crashes with `anyhow` error, not graceful degradation (line ~157)
```rust
let pf: PolicyFile = serde_yaml::from_str(&content)
    .with_context(|| format!("Failed to parse {}", path.display()))?;
```
A single malformed YAML file in the policy directory causes the entire policy engine to fail to load (returns `Err`). If `main.rs` doesn't handle this gracefully, **all policy-based detection is disabled** by one bad file.

**Fix:** Log the error and skip the bad file, continuing to load valid files. Emit a Critical alert about the malformed policy file.

#### 🐛 P-2: `command_contains` uses literal substring, not glob/regex (line ~237)
Tests in the codebase confirm: `command_contains: ["/proc/*/mem"]` matches the literal string `/proc/*/mem` but NOT `/proc/1234/mem`. The `*` is not a wildcard in substring matching.

Policy rules like `detect-binary-replacement` use `cp * /usr/bin/` — the `*` is literal and **never matches real commands**.

**Fix:** Either document this clearly (users must use exact substrings), or add glob support for `command_contains`. At minimum, fix the default policies to not use `*` in `command_contains`.

#### 🐛 P-3: Path normalization bypass in `file_access` globs (line ~242)
`glob_match` operates on raw paths. Paths like `/etc/./shadow`, `//etc/shadow`, or `/etc/../etc/shadow` will not match the glob `/etc/shadow`.

**Fix:** Canonicalize `event.file_path` before glob matching: `std::fs::canonicalize()` or at least normalize `//` and `/./` patterns.

#### 🐛 P-4: `exclude_args` only checked for `command` match, not `command_contains` or `file_access` (line ~224)
Exclude args (allowlisting) only applies when matching via exact command name. A rule using `command_contains` or `file_access` **cannot be allowlisted** — `exclude_args` is silently ignored.

**Fix:** Apply `exclude_args` check after any match type succeeds, not only command matches.

#### 🐛 P-5: `load_dirs` doesn't merge — it appends (line ~179)
```rust
engine.rules.extend(loaded.rules);
```
When loading from multiple directories, rules are appended without name-based deduplication. If the same rule name appears in different directories, both copies are kept. `evaluate()` returns the highest severity match, so the "override" intent is partially preserved, but the disabled-via-`enabled: false` pattern won't work across directories.

**Fix:** Use `merge_rules` across directories, not just within a single directory.

### 3.2 Edge Cases

#### 🔧 P-6: Empty `match_spec` matches nothing (desired, but not validated)
A rule with no `command`, `command_contains`, or `file_access` will never match anything. This is a silent no-op — no warning is logged.

**Fix:** Log a warning when loading a rule with an empty match_spec (possible config error).

#### 🔧 P-7: Conflicting severity across rules is silent
If rule A says "curl is critical" and rule B says "curl is info", highest wins. This is correct behavior, but users may not realize their override was dominated.

**Fix:** Log when multiple rules match the same event (debug level).

#### 🔧 P-8: Default action is "critical" (line ~42)
If a rule omits the `action` field, it defaults to "critical". This is a dangerous default — a typo or omission in a policy file creates a Critical-severity rule.

**Fix:** Consider defaulting to "warning" or requiring the action field explicitly.

### 3.3 Missing Capabilities

#### 🔧 P-9: No regex support in match patterns
Only exact command, substring, and file glob are supported. Many real-world patterns need regex (e.g., match PIDs in `/proc/\d+/mem`).

**Fix:** Add optional `command_regex` and `file_regex` fields.

#### 🔧 P-10: No negation / "match all except" pattern
Users can't write "alert on all curl EXCEPT to these hosts" without `exclude_args`. But `exclude_args` only works on command matches (see P-4).

#### 🔧 P-11: No action type for "suppress" / explicit allow
The only actions are severity levels. There's no way to say "this pattern is explicitly safe, suppress all other rules that would match." Enforcement rules exist but are skipped in detection.

**Fix:** Add `action: allow` that suppresses other matches for the same event.

---

## Summary

| Module | Bugs | Improvements | Style |
|--------|------|-------------|-------|
| behavior.rs | 4 | 13 | 0 |
| scanner.rs | 4 | 13 | 1 |
| policy.rs | 5 | 6 | 0 |
| **Total** | **13** | **32** | **1** |

### Priority Recommendations

**Critical (fix before next release):**
1. **P-1:** Malformed YAML disables all policy detection
2. **P-2:** `command_contains` `*` wildcard doesn't work (default policies broken)
3. **P-3:** Path normalization bypass in file_access globs
4. **S-1/S-2:** `find` and `lsof` scans silently broken (shell redirection/pipes as args)
5. **B-1:** History tamper bypass via `ln`

**High (significant detection gaps):**
6. **B-10:** No crypto miner detection
7. **B-5:** python3 -c / node -e false positive storm
8. **P-4:** exclude_args only works on command matches
9. **P-5:** load_dirs doesn't merge rules properly
10. **B-11-15:** Missing MITRE ATT&CK coverage (SUID, disk read, fileless exec, network manipulation)

**Medium (noise reduction):**
11. **S-5 through S-10:** Permanent-noise scans need configurability
12. **B-6-9:** Severity tuning for common agent operations
