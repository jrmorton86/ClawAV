# OpenClaw Security Integration

ClawAV monitors the OpenClaw agent infrastructure for security misconfigurations, credential exposure, config drift, and attack surface issues.

## What's Monitored

### Phase 1: Core Security
- **Permission checks**: `~/.openclaw` (700), `openclaw.json` (600), credentials (600), session logs (700)
- **Symlink safety**: Detects symlinks in `~/.openclaw` pointing outside the directory
- **Audit CLI integration**: Runs `openclaw security audit --deep` and ingests findings
- **Credential monitoring**: Real-time inotify on credentials, auth-profiles, config changes

### Phase 2: Config Drift Detection
- Baselines security-critical fields in `openclaw.json`
- Alerts on regressions: auth disabled, policies loosened to "open", dangerous Control UI flags
- Non-regression changes are logged and re-baselined

### Phase 3: Advanced Monitoring
- **mDNS info leak**: Detects OpenClaw services advertised via Avahi/mDNS
- **Plugin integrity**: Monitors `~/.openclaw/extensions/` for new/changed plugins
- **Control UI exposure**: Flags `dangerouslyDisableDeviceAuth` and `allowInsecureAuth`
- **Session log auditd**: Monitors reads of session transcript files

## Configuration

All features are controlled via `openclaw:` in `config.yaml`:

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Master switch for all OpenClaw checks |
| `config_path` | `~/.openclaw/openclaw.json` | Path to OpenClaw config |
| `state_dir` | `~/.openclaw` | OpenClaw state directory |
| `audit_command` | `openclaw security audit --deep` | CLI command to run |
| `audit_on_scan` | `true` | Run audit CLI during periodic scans |
| `config_drift_check` | `true` | Enable config drift detection |
| `baseline_path` | `/etc/clawav/openclaw-config-baseline.json` | Drift baseline storage |
| `mdns_check` | `false` | Check for mDNS info leaks |
| `plugin_watch` | `false` | Monitor extensions directory |
| `session_log_audit` | `false` | Enable session log auditd rules |

## Alert Categories

| Category | Severity | Description |
|----------|----------|-------------|
| `openclaw:perms:*` | FAIL/WARN | Permission issues on OpenClaw files |
| `openclaw:symlinks` | FAIL | Suspicious symlinks in state dir |
| `openclaw:audit:*` | varies | Findings from `openclaw security audit` |
| `openclaw:drift` | FAIL/WARN | Config drift (FAIL = security regression) |
| `openclaw:mdns` | WARN | mDNS service advertisement detected |
| `openclaw:extensions` | WARN | Plugin installed, needs verification |
| `openclaw:controlui` | FAIL/WARN | Dangerous Control UI settings |

## Security Fields Tracked for Drift

- `gateway.auth.mode` (regression: `none`)
- `gateway.bind` (regression: `0.0.0.0`)
- `*.dmPolicy` (regression: `open`)
- `*.groupPolicy` (regression: `open`)
- `logging.redactSensitive` (regression: `off`)
- `controlUi.dangerouslyDisableDeviceAuth` (regression: `true`)
- `controlUi.allowInsecureAuth` (regression: `true`)
