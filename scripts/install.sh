#!/usr/bin/env bash
# ClawTower Swallowed Key Installer
# Once run, ClawTower cannot be stopped/modified without physical access + recovery boot.
# This script self-destructs after successful installation.
set -euo pipefail

SCRIPT_PATH="$(readlink -f "$0")"
BINARY_SRC="$(dirname "$SCRIPT_PATH")/../target/release/clawtower"
CONFIG_SRC="$(dirname "$SCRIPT_PATH")/../config.toml"
INSTALLED_BIN="/usr/local/bin/clawtower"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[INSTALL]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
die()  { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# chattr wrapper: tries direct chattr first, falls back to systemd-run
# (bypasses dropped CAP_LINUX_IMMUTABLE in the current session's bounding set)
do_chattr() {
    local flag="$1" path="$2"
    if chattr "$flag" "$path" 2>/dev/null; then
        return 0
    fi
    systemd-run --wait --collect --quiet chattr "$flag" "$path" 2>/dev/null
}

[[ $EUID -eq 0 ]] || die "Must run as root"

# Binary: if already installed (e.g. via deploy.sh), keep it — don't overwrite
# with a potentially stale source tree build. Only copy from source on fresh install.
SKIP_BINARY_INSTALL=0
if [[ -f "$INSTALLED_BIN" ]]; then
    log "Binary already installed at $INSTALLED_BIN — keeping deployed version"
    SKIP_BINARY_INSTALL=1
elif [[ -f "$BINARY_SRC" ]]; then
    : # Fresh install from source build
else
    die "Binary not found at $BINARY_SRC or $INSTALLED_BIN — deploy first"
fi
[[ -f "$CONFIG_SRC" ]] || die "Config not found at $CONFIG_SRC"

# ── 1. Create system user ────────────────────────────────────────────────────
log "Creating clawtower system user..."
if ! id -u clawtower &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin clawtower
fi

# ── 1b. Grant sentinel read access to openclaw home ─────────────────────────
# The sentinel needs to traverse /home/openclaw to set up inotify watches on
# credential and identity files. Without this, all openclaw watches are silently
# skipped (the clawtower user can't stat paths under a 700 home directory).
AGENT_HOME="/home/${CLAWTOWER_AGENT_USER:-openclaw}"
AGENT_GROUP="${CLAWTOWER_AGENT_USER:-openclaw}"
if id -u "$AGENT_GROUP" &>/dev/null; then
    usermod -a -G "$AGENT_GROUP" clawtower 2>/dev/null \
        && log "Added clawtower to $AGENT_GROUP group" \
        || warn "Failed to add clawtower to $AGENT_GROUP group"
    # 710: owner full, group traverse, others none
    chmod 710 "$AGENT_HOME" 2>/dev/null || true
    # 750: owner full, group read+traverse for .openclaw config dir
    chmod 750 "$AGENT_HOME/.openclaw" 2>/dev/null || true
    log "Set $AGENT_HOME to 710, $AGENT_HOME/.openclaw to 750 (sentinel access)"
fi

# ── 2. Install binary and config ─────────────────────────────────────────────
log "Installing binary and config..."
systemctl stop clawtower 2>/dev/null || true
sleep 0.5
# Temporarily unload AppArmor protection profiles so cp/chattr can touch protected paths.
# These deny rules block even root. Step 5 reloads them after all modifications are done.
if command -v apparmor_parser &>/dev/null && [ -f /etc/apparmor.d/etc.clawtower.protect ]; then
    apparmor_parser -R /etc/apparmor.d/etc.clawtower.protect 2>/dev/null || true
    log "Temporarily unloaded AppArmor protection profiles"
fi
# Strip immutable flags from all protected files before touching them
do_chattr -i /usr/local/bin/clawtower || true
do_chattr -i /etc/clawtower/config.toml || true
do_chattr -i /etc/clawtower/admin.key.hash || true
do_chattr -i /etc/systemd/system/clawtower.service || true
# Create dirs after stop (systemd RuntimeDirectory cleanup deletes /var/run/clawtower)
mkdir -p /etc/clawtower /var/log/clawtower /var/run/clawtower
if [[ $SKIP_BINARY_INSTALL -eq 0 ]]; then
    rm -f /usr/local/bin/clawtower
    cp "$BINARY_SRC" /usr/local/bin/clawtower
    chmod 755 /usr/local/bin/clawtower
else
    log "Skipping binary install (already at $INSTALLED_BIN)"
fi
cp "$CONFIG_SRC" /etc/clawtower/config.toml
chmod 644 /etc/clawtower/config.toml
chown -R clawtower:clawtower /etc/clawtower /var/log/clawtower /var/run/clawtower

# Create config.d directory for user overrides
mkdir -p /etc/clawtower/config.d
chown root:root /etc/clawtower/config.d
chmod 755 /etc/clawtower/config.d
log "Created /etc/clawtower/config.d/ for user overrides"
# Allow openclaw group to connect to admin socket dir
chown clawtower:openclaw /var/run/clawtower
chmod 0750 /var/run/clawtower

# ── 3. Install systemd service ───────────────────────────────────────────────
log "Installing systemd service..."
cat > /etc/systemd/system/clawtower.service <<'EOF'
[Unit]
Description=ClawTower Security Watchdog
After=network.target auditd.service
Wants=auditd.service

[Service]
Type=simple
ExecStart=/usr/local/bin/clawtower --headless /etc/clawtower/config.toml
Restart=on-failure
RestartSec=5
KillMode=control-group
TimeoutStopSec=15
ProtectSystem=strict
ProtectHome=read-only
NoNewPrivileges=true
ReadWritePaths=/var/log/clawtower /var/run/clawtower /etc/clawtower
RuntimeDirectory=clawtower
RuntimeDirectoryMode=0750

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable clawtower

# ── 4. Set immutable attributes ──────────────────────────────────────────────
log "Setting immutable attributes (chattr +i)..."
for f in /usr/local/bin/clawtower /etc/systemd/system/clawtower.service; do
    if [[ -f "$f" ]]; then
        do_chattr +i "$f" && log "  chattr +i $f — OK" || warn "  chattr +i $f — FAILED"
    else
        warn "  $f not found, skipping chattr"
    fi
done
# admin.key.hash: chattr +i is handled by generate-key subcommand below

# ── 4b. Generate admin key (one-time, idempotent) ─────────────────────────────
log "Generating admin key..."
/usr/local/bin/clawtower generate-key || die "Admin key generation failed"

# ── 4c. Auditd tamper-detection rules ────────────────────────────────────────
log "Installing auditd tamper-detection rules..."
if command -v auditctl &>/dev/null; then
    # Check if audit rules are already locked
    AUDIT_ENABLED=$(auditctl -s 2>/dev/null | grep -oP 'enabled\s+\K\d+' || echo "0")
    if [[ "$AUDIT_ENABLED" == "2" ]]; then
        warn "  Audit rules are locked (enabled=2) — skipping rule additions (reboot to unlock)"
    else
        auditctl -l 2>/dev/null | grep -q "clawtower-tamper" \
            && log "  audit rule clawtower-tamper already exists — skipping" \
            || { auditctl -w /usr/bin/chattr -p x -k clawtower-tamper 2>/dev/null \
                && log "  audit rule: watch /usr/bin/chattr -p x -k clawtower-tamper — OK" \
                || warn "  audit rule for chattr failed"; }
        auditctl -l 2>/dev/null | grep -q "clawtower-config" \
            && log "  audit rules clawtower-config already exist — skipping" \
            || {
                auditctl -w /etc/clawtower/ -p wa -k clawtower-config 2>/dev/null \
                    && log "  audit rule: watch /etc/clawtower/ — OK" \
                    || warn "  audit rule for /etc/clawtower/ failed"
                auditctl -w /usr/local/bin/clawtower -p wa -k clawtower-config 2>/dev/null \
                    && log "  audit rule: watch /usr/local/bin/clawtower — OK" \
                    || warn "  audit rule for binary failed"
                auditctl -w /etc/systemd/system/clawtower.service -p wa -k clawtower-config 2>/dev/null \
                    && log "  audit rule: watch clawtower.service — OK" \
                    || warn "  audit rule for service file failed"
            }
    fi
else
    warn "auditctl not available — skipping tamper-detection audit rules"
fi

# ── 5. AppArmor profiles (via embedded binary) ──────────────────────────────
log "Setting up AppArmor profiles (via embedded binary)..."
/usr/local/bin/clawtower setup-apparmor --quiet \
    && log "  AppArmor/capability setup complete" \
    || warn "  AppArmor setup returned non-zero (non-fatal)"

# ── 6. Drop capabilities from openclaw user ──────────────────────────────────
log "Dropping dangerous capabilities from openclaw user..."
# capability.conf restricts caps at login
cat > /etc/security/capability.conf <<'CAPCONF'
# Drop dangerous capabilities from openclaw user
!cap_linux_immutable  openclaw
!cap_sys_ptrace       openclaw
!cap_sys_module       openclaw
CAPCONF

# NOTE: pam_cap was previously added to /etc/pam.d/common-auth, but this
# caused CAP_LINUX_IMMUTABLE to be dropped from ALL user sessions (not just
# openclaw), breaking chattr and making re-harden impossible. Removed.
# Defense layers that remain: AppArmor deny capability, clawsudo deny rules,
# chattr +i on files, kernel.modules_disabled=1.
# Clean up stale pam_cap entry from previous installs:
if grep -q pam_cap /etc/pam.d/common-auth 2>/dev/null; then
    sed -i '/pam_cap/d' /etc/pam.d/common-auth
    log "  Removed stale pam_cap.so from /etc/pam.d/common-auth"
fi

# ── 6b. Disable unnecessary services ─────────────────────────────────────────
log "Disabling unnecessary network services..."
if systemctl is-active --quiet rpcbind 2>/dev/null; then
    systemctl stop rpcbind rpcbind.socket 2>/dev/null || true
    systemctl disable rpcbind rpcbind.socket 2>/dev/null || true
    systemctl mask rpcbind rpcbind.socket 2>/dev/null || true
    log "  rpcbind disabled and masked (port 111)"
else
    log "  rpcbind already inactive"
fi

# Remove agent user from docker group (docker group = root)
AGENT_USER="${CLAWTOWER_AGENT_USER:-openclaw}"
if id -nG "$AGENT_USER" 2>/dev/null | grep -qw docker; then
    gpasswd -d "$AGENT_USER" docker 2>/dev/null || true
    log "  Removed $AGENT_USER from docker group"
else
    log "  $AGENT_USER not in docker group"
fi

# ── 7. Kernel hardening via sysctl ───────────────────────────────────────────
log "Setting kernel hardening parameters..."

# ptrace_scope: configurable — only set if not already configured or less restrictive
DESIRED_PTRACE=${CLAWTOWER_PTRACE_SCOPE:-2}
CURRENT_PTRACE=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo "0")
log "  ptrace_scope: current=$CURRENT_PTRACE desired=$DESIRED_PTRACE"
if [[ "$CURRENT_PTRACE" -ge "$DESIRED_PTRACE" ]]; then
    log "  ptrace_scope already at $CURRENT_PTRACE (>= $DESIRED_PTRACE), keeping current value"
    PTRACE_VALUE="$CURRENT_PTRACE"
else
    log "  ptrace_scope $CURRENT_PTRACE < $DESIRED_PTRACE, hardening to $DESIRED_PTRACE"
    PTRACE_VALUE="$DESIRED_PTRACE"
fi

cat > /etc/sysctl.d/99-clawtower.conf <<SYSCTL
# ClawTower kernel hardening
kernel.modules_disabled = 1
kernel.yama.ptrace_scope = ${PTRACE_VALUE}
SYSCTL
# Apply sysctl params individually for idempotency
SYSCTL_REBOOT_NEEDED=0
while IFS='=' read -r key val; do
    key=$(echo "$key" | xargs)
    val=$(echo "$val" | xargs)
    [[ -z "$key" || "$key" == \#* ]] && continue
    keypath="/proc/sys/${key//\.//}"
    current=$(cat "$keypath" 2>/dev/null || echo "")
    if [[ "$current" == "$val" ]]; then
        log "  $key already at $val — skipping"
    else
        sysctl -w "$key=$val" 2>/dev/null \
            && log "  $key set to $val" \
            || { warn "  $key=$val failed (current: $current) — needs reboot"; SYSCTL_REBOOT_NEEDED=1; }
    fi
done < /etc/sysctl.d/99-clawtower.conf
[[ $SYSCTL_REBOOT_NEEDED -eq 1 ]] && warn "Some sysctl params could not be applied at runtime — reboot recommended"

# ── 8. Restricted sudoers (Tier 1 hardened) ──────────────────────────────────
log "Installing hardened sudoers from policies/sudoers-openclaw.conf..."
# Remove old deny-list approach if present
if [[ -f /etc/sudoers.d/clawtower-deny ]]; then
    do_chattr -i /etc/sudoers.d/clawtower-deny || true
    rm -f /etc/sudoers.d/clawtower-deny
fi
SUDOERS_SRC="$(dirname "$(realpath "$0")")/../policies/sudoers-openclaw.conf"
SUDOERS_DEST="/etc/sudoers.d/010_openclaw"
do_chattr -i "$SUDOERS_DEST" || true
cp "$SUDOERS_SRC" "$SUDOERS_DEST"
chmod 0440 "$SUDOERS_DEST"
# Validate sudoers
visudo -cf "$SUDOERS_DEST" || die "Invalid sudoers file!"
do_chattr +i "$SUDOERS_DEST" || warn "chattr +i $SUDOERS_DEST — FAILED"

# ── 9. Lock audit rules ─────────────────────────────────────────────────────
log "Locking audit rules (immutable until reboot)..."
if command -v auditctl &>/dev/null; then
    AUDIT_ENABLED=$(auditctl -s 2>/dev/null | grep -oP 'enabled\s+\K\d+' || echo "0")
    if [[ "$AUDIT_ENABLED" == "2" ]]; then
        log "  Audit rules already locked (enabled=2) — skipping"
    else
        auditctl -e 2 2>/dev/null \
            && log "  Audit rules locked" \
            || warn "  Failed to lock audit rules"
    fi
else
    warn "auditctl not available — skipping audit lock"
fi

# ── 10. Start the service ────────────────────────────────────────────────────
log "Starting ClawTower service..."
systemctl start clawtower || warn "Service start failed — check 'journalctl -u clawtower'"

# ── 11. Self-destruct ────────────────────────────────────────────────────────
log "Installation complete!"
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ClawTower installed and hardened.                         ║${NC}"
echo -e "${GREEN}║  The swallowed key is now in effect.                        ║${NC}"
echo -e "${GREEN}║                                                             ║${NC}"
echo -e "${GREEN}║  To uninstall: clawtower uninstall --key <admin-key>            ║${NC}"
echo -e "${GREEN}║  Your admin key was displayed above — save it now!          ║${NC}"
echo -e "${GREEN}║  ⚠️  SAVE YOUR ADMIN KEY — it's the only way to uninstall!  ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── 12. Build and install LD_PRELOAD guard ────────────────────────────────
log "Building and installing LD_PRELOAD syscall interception..."
do_chattr -i /usr/local/lib/clawtower/libclawtower.so || true
PRELOAD_SCRIPT_DIR="$(dirname "$SCRIPT_PATH")"
if [ -f "$PRELOAD_SCRIPT_DIR/build-preload.sh" ]; then
    bash "$PRELOAD_SCRIPT_DIR/build-preload.sh"
    bash "$PRELOAD_SCRIPT_DIR/enable-preload.sh"
else
    warn "build-preload.sh not found — skipping LD_PRELOAD guard"
fi

log "Self-destructing installer..."
rm -f "$SCRIPT_PATH"
log "Done. Installer deleted."
