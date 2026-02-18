# Installation Guide

## Prerequisites

- **Rust** (stable toolchain) — for building
- **gcc** — for building `libclawtower.so`
- **auditd** — kernel audit framework (`apt install auditd`)
- **ufw** — firewall (`apt install ufw`)
- **AppArmor** (optional but recommended) — MAC profiles
- **libpam-cap** (optional) — for capability restriction via PAM

## Pre-Install Checklist

1. **Build the release binary:**
   ```bash
   cargo build --release
   ```
   Binary will be at `target/release/clawtower`

2. **Build the LD_PRELOAD library:**
   ```bash
   bash scripts/build-preload.sh
   ```
   Creates `libclawtower.so` in the project root

3. **Configure ClawTower:**
   - Don't edit `config.toml` directly — it's replaced on updates
   - Instead, create drop-in overrides:
     ```bash
     # Customize via drop-in overrides (never touched by updates)
     sudo mkdir -p /etc/clawtower/config.d
     sudo nano /etc/clawtower/config.d/my-overrides.toml
     ```
   - Set `watched_users` to the UIDs of your AI agent users (e.g., `["1000"]`), or set `watch_all_users = true`
   - Legacy: `watched_user` (single UID) is still supported but `watched_users` (list) is preferred
   - Set `slack.webhook_url` to an **independent** Slack webhook (not the agent's)
   - Optionally set `slack.backup_webhook_url` for failover
   - See [CONFIGURATION.md](CONFIGURATION.md) for full config reference and the config.d/ layering system
   - See [ALERT-PIPELINE.md](ALERT-PIPELINE.md#tuning-alerts) for alert tuning options

4. **Ensure auditd is running:**
   ```bash
   sudo systemctl status auditd
   ```

5. **Ensure ufw is active:**
   ```bash
   sudo ufw status
   ```

## Installation

```bash
sudo bash scripts/install.sh
```

### What install.sh Does (Step by Step)

**Step 1 — Create system user:**
```bash
useradd --system --no-create-home --shell /usr/sbin/nologin clawtower
```

**Step 2 — Install binary and config:**
- Copies binary to `/usr/local/bin/clawtower` (mode 755)
- Copies config to `/etc/clawtower/config.toml` (mode 644)
- Creates `/var/log/clawtower/` and `/var/run/clawtower/`
- Sets ownership: `clawtower:clawtower` (except `/var/run/clawtower/` → `clawtower:openclaw` mode 0750)

**Step 3 — Install systemd service:**
Creates `/etc/systemd/system/clawtower.service` with:
- `Restart=always`, `RestartSec=5`
- `WatchdogSec=30` (systemd kills and restarts if watchdog not fed)
- `ProtectSystem=strict`, `ProtectHome=yes`, `NoNewPrivileges=true`
- `ReadWritePaths=/var/log/clawtower /var/run/clawtower /etc/clawtower`
- Runs as user `clawtower` in `--headless` mode

**Step 4 — Set immutable attributes:**
```bash
chattr +i /usr/local/bin/clawtower
chattr +i /etc/systemd/system/clawtower.service
```
After this, even root cannot modify these files without first removing the immutable flag — and the agent's `CAP_LINUX_IMMUTABLE` is stripped in step 6. Note: `config.toml` is **not** made immutable — customize via `/etc/clawtower/config.d/` instead (see [CONFIGURATION.md](CONFIGURATION.md)).

**Step 5 — AppArmor profile:**
Creates `/etc/apparmor.d/clawtower.deny-openclaw` which denies the `openclaw` user access to:
- `/usr/local/bin/clawtower`
- `/etc/clawtower/**`
- `/var/log/clawtower/**`

**Step 6 — Drop capabilities:**
Writes `/etc/security/capability.conf`:
```
!cap_linux_immutable  openclaw
!cap_sys_ptrace       openclaw
!cap_sys_module       openclaw
```
Adds `pam_cap.so` to `/etc/pam.d/common-auth` if available.

**Step 7 — Kernel hardening:**
Creates `/etc/sysctl.d/99-clawtower.conf`:
```
kernel.modules_disabled = 1
kernel.yama.ptrace_scope = 2
```
- `modules_disabled=1` — prevents loading kernel modules (irreversible until reboot)
- `ptrace_scope=2` — only root can ptrace (prevents debugging the watchdog)

**Step 8 — Restricted sudoers:**
Creates `/etc/sudoers.d/clawtower-deny` denying the `openclaw` user from running:
- `systemctl stop/disable/mask clawtower`
- `chattr -i` on any ClawTower files
- `ufw disable`
- `auditctl -e 0` or `auditctl -e 1`

The sudoers file itself is made immutable with `chattr +i`.

**Step 9 — Lock audit rules:**
```bash
auditctl -e 2
```
Makes audit rules immutable until next reboot.

**Step 10 — Start the service.**

**Step 11 — Build and install LD_PRELOAD guard:**
Runs `build-preload.sh` and `enable-preload.sh`:
- Compiles `libclawtower.so` and installs to `/usr/local/lib/clawtower/`
- Creates default preload policy at `/etc/clawtower/preload-policy.json`
- Adds `Environment=LD_PRELOAD=...` to the systemd service
- Makes `libclawtower.so` immutable

**Step 12 — Self-destruct:**
```bash
rm -f "$SCRIPT_PATH"
```

## What Happens on First Run

1. ClawTower loads `/etc/clawtower/config.toml` — **if this file is missing or invalid TOML, it will fail to start**.
2. An admin key is generated (format: `OCAV-` + 64 hex chars), printed to stdout/journal **exactly once**, and stored as an Argon2 hash at `/etc/clawtower/admin.key.hash`.
3. Shadow copies are created for all sentinel-watched files.
4. Cognitive baselines (SHA-256 hashes) are computed for identity files.
5. All enabled monitoring sources start tailing their respective logs.
6. A startup alert is sent to Slack (if configured): `"🛡️ ClawTower watchdog started"`.

> ⚠️ **Capture the admin key immediately** from `journalctl -u clawtower` — it is never shown again.

## Post-Install Verification

```bash
# Check service is running
sudo systemctl status clawtower

# Check logs
sudo journalctl -u clawtower -f

# Verify immutable flags
lsattr /usr/local/bin/clawtower
# Should show: ----i---------e------- /usr/local/bin/clawtower

# Test the API
curl http://localhost:18791/api/status

# Verify audit chain
/usr/local/bin/clawtower verify-audit
```

## CLI Commands

After installation, ClawTower provides these commands:

| Command | Description |
|---------|-------------|
| `clawtower run` | Start with TUI dashboard (default) |
| `clawtower run --headless` | Start in headless/daemon mode |
| `clawtower scan` | One-shot security scan and exit |
| `clawtower status` | Show service status |
| `clawtower configure` | Interactive configuration wizard |
| `clawtower update` | Self-update from GitHub releases |
| `clawtower verify-audit` | Verify audit chain integrity |
| `clawtower sync` | Update BarnacleDefense pattern databases |
| `clawtower harden` | Apply tamper-proof hardening |
| `clawtower uninstall` | Remove ClawTower (requires admin key) |
| `clawtower logs` | Tail service logs |

## See Also

- [ARCHITECTURE.md](ARCHITECTURE.md) — Module overview and data flow
- [ALERT-PIPELINE.md](ALERT-PIPELINE.md) — Alert flow and tuning
- [SENTINEL.md](SENTINEL.md) — File integrity monitoring
- [CONFIGURATION.md](CONFIGURATION.md) — Full config reference
- [CLAWSUDO-AND-POLICY.md](CLAWSUDO-AND-POLICY.md) — clawsudo, admin key, LD_PRELOAD guard

## ⚠️ The Admin Key — SAVE IT!

On first run, the service prints a 256-bit admin key to its log output:

```
OCAV-<64 hex characters>
```

**This key is shown exactly once.** It's stored only as an Argon2 hash in `/etc/clawtower/admin.key.hash`. You need this key to:
- Check watchdog status remotely
- Trigger manual scans
- Temporarily pause monitoring (max 30 min)

Check `journalctl -u clawtower` immediately after install to capture it.

## Recovery Procedure

To modify ClawTower after installation:

1. **Reboot into recovery mode** (physical access required)
2. Mount filesystem read-write
3. Remove immutable flags: `chattr -i /usr/local/bin/clawtower /etc/systemd/system/clawtower.service`
4. Make changes
5. Re-apply immutable flags: `chattr +i ...`
6. Reboot normally

This is by design — the "swallowed key" pattern means no software-only path can modify the watchdog.

## Uninstall

Requires physical access + recovery boot:

```bash
# In recovery mode:
chattr -i /usr/local/bin/clawtower
chattr -i /etc/systemd/system/clawtower.service
chattr -i /etc/sudoers.d/clawtower-deny
chattr -i /usr/local/lib/clawtower/libclawtower.so

systemctl stop clawtower
systemctl disable clawtower
rm /etc/systemd/system/clawtower.service
rm /usr/local/bin/clawtower
rm -rf /etc/clawtower
rm -rf /var/log/clawtower
rm -rf /var/run/clawtower
rm /etc/sudoers.d/clawtower-deny
rm /etc/apparmor.d/clawtower.deny-openclaw
rm /etc/sysctl.d/99-clawtower.conf
rm /etc/security/capability.conf
rm -rf /usr/local/lib/clawtower

userdel clawtower
systemctl daemon-reload

# Revert sysctl (will take effect on next boot):
# Remove kernel.modules_disabled and ptrace_scope from sysctl
```

## Release Signing & Key Rotation

ClawTower release binaries are signed with Ed25519. The public key is embedded in the binary at compile time (`src/release-key.pub`), and the auto-updater verifies `.sig` files from GitHub releases before applying updates.

### How It Works

1. CI reads the hex-encoded private key from the `RELEASE_SIGNING_KEY` GitHub secret
2. Each release binary is hashed (SHA-256), then the hash is signed with Ed25519
3. The 64-byte `.sig` file is attached to the GitHub release alongside the binary
4. The updater downloads the `.sig`, verifies against the embedded public key, and refuses to install if verification fails

### Key Rotation Procedure

If the signing key is compromised or needs rotation:

1. **Generate a new Ed25519 keypair:**
   ```python
   from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
   from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
   import os
   priv = Ed25519PrivateKey.generate()
   pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
   priv_bytes = priv.private_bytes(
       Encoding.Raw,
       cryptography.hazmat.primitives.serialization.PrivateFormat.Raw,
       cryptography.hazmat.primitives.serialization.NoEncryption()
   )
   print("Private (hex, for GitHub secret):", priv_bytes.hex())
   print("Public (hex):", pub_bytes.hex())
   open("src/release-key.pub", "wb").write(pub_bytes)
   ```

2. **Replace `src/release-key.pub`** with the new 32-byte public key

3. **Update the `RELEASE_SIGNING_KEY` secret** in GitHub repo settings with the new hex-encoded private key

4. **Cut a new release** — this is the transition release. Existing installations will:
   - Download the new binary (verified by SHA-256 checksum)
   - The old embedded key will fail `.sig` verification, but signature verification is non-blocking for one transition release (warns but proceeds if checksum passes)
   - After updating, the new binary has the new public key embedded

5. **All subsequent releases** will be fully verified with the new key

> **Important:** The private key must NEVER be committed to the repository. Store it only in GitHub Secrets (`RELEASE_SIGNING_KEY`) as a hex-encoded string.

## See Also

- [CONFIGURATION.md](CONFIGURATION.md) — Full config reference for every TOML field
- [SENTINEL.md](SENTINEL.md) — Setting up real-time file integrity monitoring
- [MONITORING-SOURCES.md](MONITORING-SOURCES.md) — Enabling auditd, Falco, Samhain, and other sources
- [CLAWSUDO-AND-POLICY.md](CLAWSUDO-AND-POLICY.md) — clawsudo setup and admin key details
- [INDEX.md](INDEX.md) — Full documentation index
