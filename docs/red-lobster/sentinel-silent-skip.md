# Sentinel Silent Skip — Why OpenClaw File Watches Never Worked

## The Bug

The sentinel configured watches for 33+ paths including critical openclaw
credential files (`device.json`, `openclaw.json`, `auth-profiles.json`, etc.).
All appeared to be working — the sentinel logged "Sentinel watching 33 paths"
on startup. But **none of the openclaw file watches were actually active.**

## Root Cause

```
/home/openclaw       → 700 openclaw:openclaw
/home/openclaw/.openclaw → 700 openclaw:openclaw
device.json          → 600 openclaw:openclaw
```

The `clawtower` service runs as user `clawtower` (uid 997). This user:
- Cannot traverse `/home/openclaw` (no `+x` for others on a 700 directory)
- Cannot read `/home/openclaw/.openclaw` directory listing
- Cannot stat or read any files inside

### Why It Was Silent

The sentinel watch setup code:
```rust
let dir = p.parent().unwrap_or(p);
if watched_dirs.insert(dir.to_path_buf()) && dir.exists() {
    watcher.watch(dir, RecursiveMode::NonRecursive)?;
}
```

`dir.exists()` returns `false` when the clawtower user can't stat the path
(permission denied looks like "doesn't exist" to a non-privileged user). The
watch is simply skipped — no error, no warning, no alert.

The sentinel then logs "Sentinel watching 33 paths" — counting configured
paths, not successfully registered inotify watches.

## Impact

Every sentinel watch under `/home/openclaw/` was silently non-functional:
- `device.json` (Protected) — modifications not detected
- `openclaw.json` (Watched) — modifications not detected
- `credentials/*.json` (Protected) — modifications not detected
- `auth-profiles.json` (Watched) — modifications not detected
- `SOUL.md`, `IDENTITY.md`, etc. (Protected) — modifications not detected
- All persistence paths under openclaw home — not watched

This means the sentinel's file integrity monitoring for the AI agent's most
sensitive files was **completely non-operational** since deployment.

## Detection

Red Lobster v8 flag17 test 19: `echo '// tampered' >> device.json` was not
detected. All other flag17 tests passed via auditd/behavior detection, masking
the sentinel's failure.

## Fix

### 1. Grant sentinel access (install.sh)
```bash
usermod -a -G openclaw clawtower  # Add to openclaw group
chmod 710 /home/openclaw           # Group can traverse
chmod 750 /home/openclaw/.openclaw # Group can read
```

### 2. Log skipped watches (sentinel.rs)
Changed from silent skip to warning alerts:
```rust
if !dir.exists() {
    skipped += 1;
    continue;
}
// ...
if skipped > 0 {
    alert_tx.send(Alert::new(Warning, "sentinel",
        &format!("Skipped {} watch paths (permission or missing)", skipped)));
}
```

### 3. Fix watch error handling
Changed `watcher.watch()` from `?` (propagate error, kill sentinel) to
per-path error logging with continued operation.

## Lesson

**"Watching 33 paths" was a lie.** The count reflected configuration intent,
not operational reality. Monitoring systems must verify their own effectiveness:
- Count successful vs failed watch registrations separately
- Alert when watches can't be established
- Include a self-test (write to a watched file, verify alert fires)
