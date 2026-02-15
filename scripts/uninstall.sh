#!/usr/bin/env bash
# ClawAV Uninstaller
#
# Reverses the "swallowed key" hardening from install.sh.
# Requires the admin key that was displayed on first run.
# Do NOT run with sudo — the script handles privilege escalation internally.
#
# Usage:
#   bash scripts/uninstall.sh
#   bash scripts/uninstall.sh --key <admin-key>
#   bash scripts/uninstall.sh --force   (skip key check — emergency only)
#
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[UNINSTALL]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
info() { echo -e "${CYAN}[INFO]${NC} $*"; }
die()  { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

ADMIN_KEY=""
FORCE=false
KEEP_DATA=false

for arg in "$@"; do
    case "$arg" in
        --force)
            FORCE=true
            ;;
        --keep-data)
            KEEP_DATA=true
            ;;
        --key)
            # Next arg is the key (handled below)
            ;;
        --help|-h)
            echo "Usage: bash uninstall.sh [OPTIONS]"
            echo ""
            echo "  --key <key>    Provide admin key (or will be prompted)"
            echo "  --keep-data    Keep logs and audit chain"
            echo "  --force        Skip key verification (emergency only)"
            echo ""
            exit 0
            ;;
        OCAV-*|clawav_admin_*)
            ADMIN_KEY="$arg"
            ;;
    esac
done

# Also handle --key <value> format
while [[ $# -gt 0 ]]; do
    case "$1" in
        --key)
            ADMIN_KEY="${2:-}"
            shift 2 || true
            ;;
        *)
            shift
            ;;
    esac
done

# Don't require root upfront — we verify the key as the normal user,
# then use sudo internally for privileged operations.
if [[ $EUID -eq 0 ]]; then
    warn "Running as root. Key verification works best as your normal user."
    warn "Consider running without sudo: bash scripts/uninstall.sh"
fi

echo ""
echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║           🛡️  ClawAV Uninstaller                            ║${NC}"
echo -e "${RED}║                                                              ║${NC}"
echo -e "${RED}║  This will reverse all hardening and remove ClawAV.          ║${NC}"
echo -e "${RED}║  The security watchdog will no longer protect this system.   ║${NC}"
echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Verify Admin Key ─────────────────────────────────────────────────────────
KEY_HASH_PATH="/etc/clawav/admin.key.hash"

if ! $FORCE; then
    if [[ ! -f "$KEY_HASH_PATH" ]]; then
        warn "No admin key hash found at $KEY_HASH_PATH"
        warn "ClawAV may not have been hardened (install.sh not run)"
        echo ""
        read -rp "Continue with uninstall anyway? [y/N]: " confirm
        [[ "$confirm" =~ ^[Yy] ]] || exit 0
    else
        # Prompt for key if not provided
        if [[ -z "$ADMIN_KEY" ]]; then
            echo -e "${CYAN}Enter your ClawAV admin key:${NC}"
            read -r -p "> " ADMIN_KEY
        fi

        [[ -n "$ADMIN_KEY" ]] || die "No admin key provided"

        # Verify using clawav verify-key
        CLAWAV_BIN="$(command -v clawav 2>/dev/null || true)"
        if [[ ! -x "$CLAWAV_BIN" ]]; then
            # Try to find it in common locations
            for candidate in /usr/local/bin/clawav /home/openclaw/bin/clawav ./target/release/clawav /home/openclaw/.openclaw/workspace/openclawav/target/release/clawav; do
                if [[ -x "$candidate" ]]; then
                    CLAWAV_BIN="$candidate"
                    break
                fi
            done
        fi

        if echo "$ADMIN_KEY" | "$CLAWAV_BIN" verify-key; then
            log "✅ Admin key verified"
        else
            die "❌ Invalid admin key. Uninstall denied."
        fi
    fi
else
    warn "⚠️  --force mode: skipping key verification"
    echo ""
    read -rp "Type 'FORCE UNINSTALL' to confirm: " confirm
    [[ "$confirm" == "FORCE UNINSTALL" ]] || exit 0
fi

echo ""
log "Starting uninstall..."
log "Sudo access is required for privileged operations — you may be prompted."
echo ""

# ── 1. Stop the service ──────────────────────────────────────────────────────
log "Stopping ClawAV service..."
sudo systemctl stop clawav 2>/dev/null || true
sudo systemctl disable clawav 2>/dev/null || true

# ── 2. Remove immutable attributes ───────────────────────────────────────────
log "Removing immutable attributes..."
sudo chattr -i /usr/local/bin/clawav 2>/dev/null || true
sudo chattr -i /usr/local/bin/clawsudo 2>/dev/null || true
sudo chattr -i /usr/local/bin/clawav-tray 2>/dev/null || true
sudo chattr -i /etc/clawav/config.toml 2>/dev/null || true
sudo chattr -i /etc/clawav/admin.key.hash 2>/dev/null || true
sudo chattr -i /etc/systemd/system/clawav.service 2>/dev/null || true
sudo chattr -i /etc/sudoers.d/clawav-deny 2>/dev/null || true
sudo chattr -i /etc/sudoers.d/010_pi-nopasswd 2>/dev/null || true

# ── 3. Remove AppArmor profile ───────────────────────────────────────────────
log "Removing AppArmor profile..."
if command -v apparmor_parser &>/dev/null; then
    # Current name (installer creates clawav.deny-agent)
    sudo apparmor_parser -R /etc/apparmor.d/clawav.deny-agent 2>/dev/null || true
    sudo rm -f /etc/apparmor.d/clawav.deny-agent
    # Legacy names from older installs
    sudo apparmor_parser -R /etc/apparmor.d/clawav.deny-openclaw 2>/dev/null || true
    sudo rm -f /etc/apparmor.d/clawav.deny-openclaw
    sudo rm -f /etc/apparmor.d/etc.clawav.protect
fi

# ── 4. Remove sudoers restrictions ───────────────────────────────────────────
log "Removing sudoers restrictions..."
sudo rm -f /etc/sudoers.d/clawav-deny
sudo rm -f /etc/sudoers.d/010_pi-nopasswd

# ── 5. Remove kernel hardening ───────────────────────────────────────────────
log "Removing kernel hardening sysctl..."
sudo rm -f /etc/sysctl.d/99-clawav.conf
# Restore default ptrace scope
sudo sysctl -w kernel.yama.ptrace_scope=1 2>/dev/null || true
# Note: kernel.modules_disabled=1 cannot be undone without reboot
warn "kernel.modules_disabled may still be active — reboot to restore module loading"

# ── 6. Remove capability restrictions ────────────────────────────────────────
log "Removing capability restrictions..."
if [[ -f /etc/security/capability.conf ]]; then
    sudo sed -i '/clawav\|openclaw.*cap_linux_immutable\|openclaw.*cap_sys_ptrace\|openclaw.*cap_sys_module/d' /etc/security/capability.conf 2>/dev/null || true
fi
# Remove pam_cap line we added
sudo sed -i '/pam_cap.so.*# ClawAV/d' /etc/pam.d/common-auth 2>/dev/null || true

# ── 7. Remove LD_PRELOAD guard ───────────────────────────────────────────────
log "Removing LD_PRELOAD guard..."
sudo rm -f /usr/local/lib/libclawguard.so
if [[ -f /etc/ld.so.preload ]]; then
    sudo sed -i '/libclawguard/d' /etc/ld.so.preload
    # Remove file if empty
    [[ -s /etc/ld.so.preload ]] || sudo rm -f /etc/ld.so.preload
fi

# ── 8. Remove systemd service ────────────────────────────────────────────────
log "Removing systemd service..."
sudo rm -f /etc/systemd/system/clawav.service
sudo systemctl daemon-reload

# ── 9. Remove tray autostart + binary ────────────────────────────────────────
log "Removing tray components..."
# Find the calling user's home for autostart cleanup
CALLING_USER="${SUDO_USER:-$USER}"
CALLING_HOME=$(eval echo "~$CALLING_USER")
sudo rm -f "$CALLING_HOME/.config/autostart/clawav-tray.desktop" 2>/dev/null || true

# ── 10. Remove binaries ──────────────────────────────────────────────────────
log "Removing binaries..."
sudo rm -f /usr/local/bin/clawav
sudo rm -f /usr/local/bin/clawsudo
sudo rm -f /usr/local/bin/clawav-tray

# ── 11. Warn about quarantined files ──────────────────────────────────────────
if [[ -d /etc/clawav/quarantine ]] && [[ -n "$(ls -A /etc/clawav/quarantine 2>/dev/null)" ]]; then
    warn "Quarantined files found in /etc/clawav/quarantine/:"
    ls -la /etc/clawav/quarantine/ 2>/dev/null | head -10
    echo ""
    warn "These are files ClawAV intercepted as threats."
    warn "They will be deleted. Copy them out now if you need them."
    read -rp "Continue? [Y/n]: " confirm
    [[ "$confirm" =~ ^[Nn] ]] && { info "Aborting. Move files from /etc/clawav/quarantine/ first."; exit 0; }
fi

# ── 12. Remove config ────────────────────────────────────────────────────────
log "Removing configuration..."
sudo rm -rf /etc/clawav

# ── 13. Remove data (unless --keep-data) ─────────────────────────────────────
if $KEEP_DATA; then
    info "Keeping logs and audit data at /var/log/clawav/"
else
    log "Removing logs and audit data..."
    sudo rm -rf /var/log/clawav
fi
sudo rm -rf /var/run/clawav

# ── 15. Remove clawav system user ────────────────────────────────────────────
if id -u clawav &>/dev/null; then
    log "Removing clawav system user..."
    sudo userdel clawav 2>/dev/null || true
fi

# ── 14. Remove audit rules file ───────────────────────────────────────────────
log "Removing audit rules..."
sudo rm -f /etc/audit/rules.d/clawav.rules
if command -v auditctl &>/dev/null; then
    sudo augenrules --load 2>/dev/null || true
    sudo auditctl -e 1 2>/dev/null || warn "Audit rules locked — will unlock on reboot"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ✅ ClawAV uninstalled successfully                         ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}║  Removed:                                                    ║${NC}"
echo -e "${GREEN}║    • Binaries (clawav, clawsudo, clawav-tray)               ║${NC}"
echo -e "${GREEN}║    • Config + quarantine (/etc/clawav/)                     ║${NC}"
echo -e "${GREEN}║    • Systemd service                                        ║${NC}"
echo -e "${GREEN}║    • Tray autostart entry                                   ║${NC}"
echo -e "${GREEN}║    • AppArmor profile (clawav.deny-agent)                   ║${NC}"
echo -e "${GREEN}║    • Sudoers (clawav-deny + 010_pi-nopasswd)                ║${NC}"
echo -e "${GREEN}║    • Kernel hardening sysctl                                ║${NC}"
echo -e "${GREEN}║    • LD_PRELOAD guard                                       ║${NC}"
echo -e "${GREEN}║    • Audit rules (/etc/audit/rules.d/clawav.rules)          ║${NC}"
echo -e "${GREEN}║    • Immutable file attributes                              ║${NC}"
if ! $KEEP_DATA; then
echo -e "${GREEN}║    • Logs and audit chain                                   ║${NC}"
fi
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}║  ⚠️  Reboot recommended to fully restore:                    ║${NC}"
echo -e "${GREEN}║    • Kernel module loading                                  ║${NC}"
echo -e "${GREEN}║    • Audit rule locks                                       ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
