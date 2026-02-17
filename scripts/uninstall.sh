#!/usr/bin/env bash
# ClawTower Uninstaller
#
# Complete reversal of install.sh + all setup scripts.
# Interactive: asks before removing each module/plugin.
# Requires the admin key that was displayed on first run.
#
# Usage:
#   bash scripts/uninstall.sh
#   bash scripts/uninstall.sh --key <admin-key>
#   bash scripts/uninstall.sh --force       (skip key check — emergency only)
#   bash scripts/uninstall.sh --yes         (skip per-module prompts)
#   bash scripts/uninstall.sh --keep-data   (preserve logs/audit chain)
#
set -euo pipefail

# ── Logging ──────────────────────────────────────────────────────────────────
UNINSTALL_LOG="/var/log/clawtower/uninstall-$(date +%Y%m%d-%H%M%S).log"
mkdir -p /var/log/clawtower 2>/dev/null || UNINSTALL_LOG="/tmp/clawtower-uninstall-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$UNINSTALL_LOG") 2>&1
echo "Uninstall log: $UNINSTALL_LOG"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[UNINSTALL]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
info() { echo -e "${CYAN}[INFO]${NC} $*"; }
die()  { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ── Args ─────────────────────────────────────────────────────────────────────
ADMIN_KEY=""
FORCE=false
KEEP_DATA=false
YES_ALL=false

for arg in "$@"; do
    case "$arg" in
        --force)     FORCE=true ;;
        --keep-data) KEEP_DATA=true ;;
        --yes|-y)    YES_ALL=true ;;
        --help|-h)
            echo "Usage: bash uninstall.sh [OPTIONS]"
            echo ""
            echo "  --key <key>    Provide admin key (or will be prompted)"
            echo "  --keep-data    Keep logs and audit chain"
            echo "  --force        Skip key verification (emergency only)"
            echo "  --yes, -y      Skip per-module confirmation prompts"
            echo ""
            exit 0
            ;;
        OCAV-*|clawtower_admin_*)
            ADMIN_KEY="$arg"
            ;;
    esac
done

# Handle --key <value> format
ARGS=("$@")
for ((i=0; i<${#ARGS[@]}; i++)); do
    if [[ "${ARGS[$i]}" == "--key" ]] && [[ $((i+1)) -lt ${#ARGS[@]} ]]; then
        ADMIN_KEY="${ARGS[$((i+1))]}"
    fi
done

# ── Helper: ask user (respects --yes) ────────────────────────────────────────
ask() {
    local prompt="$1"
    local default="${2:-y}"
    if $YES_ALL; then
        return 0
    fi
    local yn="[Y/n]"
    [[ "$default" == "n" ]] && yn="[y/N]"
    read -rp "$(echo -e "${CYAN}$prompt${NC} $yn: ")" answer
    answer="${answer:-$default}"
    [[ "$answer" =~ ^[Yy] ]]
}

# ── Detect target user(s) ───────────────────────────────────────────────────
# The install hardened specific users. Detect who was targeted.
detect_target_users() {
    local users=()
    # Check sudoers for restricted users
    if [[ -f /etc/sudoers.d/010_openclaw ]]; then
        while IFS= read -r line; do
            local u=$(echo "$line" | grep -oP '^\w+(?=\s+ALL)' || true)
            [[ -n "$u" && "$u" != "#" ]] && users+=("$u")
        done < /etc/sudoers.d/010_openclaw
    fi
    # Check capability.conf
    if [[ -f /etc/security/capability.conf ]]; then
        while IFS= read -r line; do
            local u=$(echo "$line" | grep -oP '!cap_\w+\s+\K\w+' || true)
            [[ -n "$u" ]] && users+=("$u")
        done < /etc/security/capability.conf
    fi
    # Deduplicate
    printf '%s\n' "${users[@]}" 2>/dev/null | sort -u
}

# ── Banner ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║           🛡️  ClawTower Complete Uninstaller                 ║${NC}"
echo -e "${RED}║                                                              ║${NC}"
echo -e "${RED}║  This will reverse ALL hardening and remove ClawTower.       ║${NC}"
echo -e "${RED}║  You'll be asked about each module before removal.           ║${NC}"
echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Verify Admin Key ─────────────────────────────────────────────────────────
KEY_HASH_PATH="/etc/clawtower/admin.key.hash"

if ! $FORCE; then
    if [[ ! -f "$KEY_HASH_PATH" ]]; then
        warn "No admin key hash found at $KEY_HASH_PATH"
        warn "ClawTower may not have been fully installed"
        echo ""
        ask "Continue with uninstall anyway?" "n" || exit 0
    else
        if [[ -z "$ADMIN_KEY" ]]; then
            echo -e "${CYAN}Enter your ClawTower admin key:${NC}"
            read -r -p "> " ADMIN_KEY
        fi

        [[ -n "$ADMIN_KEY" ]] || die "No admin key provided"

        CLAWTOWER_BIN="$(command -v clawtower 2>/dev/null || true)"
        if [[ ! -x "$CLAWTOWER_BIN" ]]; then
            for candidate in /usr/local/bin/clawtower ./target/release/clawtower; do
                if [[ -x "$candidate" ]]; then
                    CLAWTOWER_BIN="$candidate"
                    break
                fi
            done
        fi

        if [[ -x "$CLAWTOWER_BIN" ]] && echo "$ADMIN_KEY" | "$CLAWTOWER_BIN" verify-key; then
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
log "Sudo access is required for privileged operations."
echo ""

# Detect targeted users
TARGET_USERS=($(detect_target_users))
if [[ ${#TARGET_USERS[@]} -eq 0 ]]; then
    TARGET_USERS=("openclaw")
    info "No restricted users detected, defaulting to: openclaw"
else
    info "Detected restricted user(s): ${TARGET_USERS[*]}"
fi

# Track what we removed for the summary
REMOVED=()
SKIPPED=()
REBOOT_REASONS=()

# ══════════════════════════════════════════════════════════════════════════════
# MODULE: Core Service
# ══════════════════════════════════════════════════════════════════════════════
echo ""
info "── Core Service ──"
if systemctl list-unit-files clawtower.service &>/dev/null 2>&1; then
    log "Stopping and disabling ClawTower service..."
    sudo systemctl stop clawtower 2>/dev/null || true
    sudo systemctl disable clawtower 2>/dev/null || true
    REMOVED+=("systemd service (stopped + disabled)")
else
    info "ClawTower service not found"
fi

# ══════════════════════════════════════════════════════════════════════════════
# MODULE: Immutable File Attributes
# ══════════════════════════════════════════════════════════════════════════════
echo ""
info "── Immutable File Attributes ──"
log "Removing immutable/append-only flags from all ClawTower files..."
for f in /usr/local/bin/clawtower /usr/local/bin/clawsudo /usr/local/bin/clawtower-tray \
         /etc/clawtower/admin.key.hash /etc/clawtower/config.toml \
         /etc/systemd/system/clawtower.service \
         /etc/sudoers.d/clawtower-deny /etc/sudoers.d/010_openclaw \
         /etc/sudoers.d/010_pi-nopasswd \
         /usr/local/lib/clawtower/libclawguard.so /usr/local/lib/libclawguard.so; do
    if [[ -f "$f" ]]; then
        sudo chattr -ia "$f" 2>/dev/null && log "  chattr -ia $f" || true
    fi
done
# Also clear any remaining immutable flags in config dir
sudo find /etc/clawtower -type f -exec chattr -ia {} \; 2>/dev/null || true
REMOVED+=("immutable file attributes")

# ══════════════════════════════════════════════════════════════════════════════
# MODULE: clawsudo
# ══════════════════════════════════════════════════════════════════════════════
echo ""
info "── clawsudo (sudo proxy/gatekeeper) ──"
if [[ -f /usr/local/bin/clawsudo ]]; then
    info "clawsudo is installed at /usr/local/bin/clawsudo"
    info "It acts as a policy-gated sudo proxy for restricted users."
    if ask "Remove clawsudo?"; then
        sudo rm -f /usr/local/bin/clawsudo
        log "  Removed /usr/local/bin/clawsudo"
        REMOVED+=("clawsudo binary")
    else
        SKIPPED+=("clawsudo")
    fi
else
    info "clawsudo not found — skipping"
fi

# ══════════════════════════════════════════════════════════════════════════════
# MODULE: Sudoers Restrictions → Restore Full Sudo
# ══════════════════════════════════════════════════════════════════════════════
echo ""
info "── Sudoers Restrictions ──"
SUDOERS_CHANGED=false

# Remove ClawTower deny file
if [[ -f /etc/sudoers.d/clawtower-deny ]]; then
    info "Found /etc/sudoers.d/clawtower-deny (deny-list style)"
    if ask "Remove clawtower-deny sudoers restrictions?"; then
        sudo chattr -ia /etc/sudoers.d/clawtower-deny 2>/dev/null || true
        sudo rm -f /etc/sudoers.d/clawtower-deny
        log "  Removed clawtower-deny"
        SUDOERS_CHANGED=true
    fi
fi

# Remove hardened allowlist sudoers
if [[ -f /etc/sudoers.d/010_openclaw ]]; then
    info "Found /etc/sudoers.d/010_openclaw (allowlist-based, routes through clawsudo)"
    if ask "Remove hardened sudoers allowlist?"; then
        sudo chattr -ia /etc/sudoers.d/010_openclaw 2>/dev/null || true
        sudo rm -f /etc/sudoers.d/010_openclaw
        log "  Removed 010_openclaw"
        SUDOERS_CHANGED=true
    fi
fi

# Remove pi-specific sudoers if present
if [[ -f /etc/sudoers.d/010_pi-nopasswd ]]; then
    info "Found /etc/sudoers.d/010_pi-nopasswd"
    if ask "Remove pi-nopasswd sudoers file?"; then
        sudo chattr -ia /etc/sudoers.d/010_pi-nopasswd 2>/dev/null || true
        sudo rm -f /etc/sudoers.d/010_pi-nopasswd
        log "  Removed 010_pi-nopasswd"
        SUDOERS_CHANGED=true
    fi
fi

# Restore full sudo privileges for targeted users
if $SUDOERS_CHANGED; then
    echo ""
    info "The following user(s) had restricted sudo: ${TARGET_USERS[*]}"
    for user in "${TARGET_USERS[@]}"; do
        if id "$user" &>/dev/null; then
            if ask "Restore full NOPASSWD sudo for '$user'?"; then
                echo "$user ALL=(ALL) NOPASSWD: ALL" | sudo tee "/etc/sudoers.d/010_${user}" > /dev/null
                sudo chmod 0440 "/etc/sudoers.d/010_${user}"
                sudo visudo -cf "/etc/sudoers.d/010_${user}" || {
                    warn "Invalid sudoers file for $user — removing"
                    sudo rm -f "/etc/sudoers.d/010_${user}"
                }
                log "  Restored full sudo for $user"
                REMOVED+=("sudo restrictions for $user → full access restored")
            else
                warn "  $user still has NO sudo access (old rules removed, no replacement)"
                SKIPPED+=("sudo restore for $user")
            fi
        else
            info "  User '$user' doesn't exist on this system — skipping"
        fi
    done
else
    SKIPPED+=("sudoers (no changes)")
fi

# ══════════════════════════════════════════════════════════════════════════════
# MODULE: AppArmor Profiles
# ══════════════════════════════════════════════════════════════════════════════
echo ""
info "── AppArmor Profiles ──"
APPARMOR_PROFILES=(
    "/etc/apparmor.d/clawtower.deny-openclaw"
    "/etc/apparmor.d/clawtower.deny-agent"
    "/etc/apparmor.d/etc.clawtower.protect"
    "/etc/apparmor.d/usr.bin.openclaw"
)
APPARMOR_FOUND=false
for profile in "${APPARMOR_PROFILES[@]}"; do
    if [[ -f "$profile" ]]; then
        APPARMOR_FOUND=true
        info "Found AppArmor profile: $(basename "$profile")"
    fi
done

if $APPARMOR_FOUND; then
    info "These profiles restrict user access to ClawTower paths and protect config files."
    if ask "Remove all ClawTower AppArmor profiles?"; then
        if command -v apparmor_parser &>/dev/null; then
            for profile in "${APPARMOR_PROFILES[@]}"; do
                if [[ -f "$profile" ]]; then
                    sudo apparmor_parser -R "$profile" 2>/dev/null \
                        && log "  Unloaded $(basename "$profile")" \
                        || warn "  Could not unload $(basename "$profile") (may need reboot)"
                    sudo rm -f "$profile"
                    log "  Deleted $profile"
                fi
            done
        else
            # No parser — just delete the files
            for profile in "${APPARMOR_PROFILES[@]}"; do
                sudo rm -f "$profile"
            done
            warn "apparmor_parser not found — deleted profile files but could not unload from kernel"
            REBOOT_REASONS+=("AppArmor profiles deleted but not unloaded")
        fi
        REMOVED+=("AppArmor profiles")
    else
        SKIPPED+=("AppArmor profiles")
    fi
else
    info "No ClawTower AppArmor profiles found"
fi

# ══════════════════════════════════════════════════════════════════════════════
# MODULE: LD_PRELOAD Guard (libclawguard.so)
# ══════════════════════════════════════════════════════════════════════════════
echo ""
info "── LD_PRELOAD Guard (libclawguard.so) ──"
PRELOAD_FOUND=false
PRELOAD_PATHS=("/usr/local/lib/clawtower/libclawguard.so" "/usr/local/lib/libclawguard.so")
for p in "${PRELOAD_PATHS[@]}"; do
    [[ -f "$p" ]] && PRELOAD_FOUND=true
done
# Also check ld.so.preload
if [[ -f /etc/ld.so.preload ]] && grep -q "libclawguard" /etc/ld.so.preload 2>/dev/null; then
    PRELOAD_FOUND=true
fi

if $PRELOAD_FOUND; then
    info "libclawguard.so intercepts syscalls at libc level for the agent user."
    if ask "Remove LD_PRELOAD guard?"; then
        for p in "${PRELOAD_PATHS[@]}"; do
            if [[ -f "$p" ]]; then
                sudo chattr -ia "$p" 2>/dev/null || true
                sudo rm -f "$p"
                log "  Removed $p"
            fi
        done
        # Clean up the preload-policy.json
        sudo rm -f /etc/clawtower/preload-policy.json 2>/dev/null || true
        # Remove directory if empty
        sudo rmdir /usr/local/lib/clawtower 2>/dev/null || true
        # Remove from ld.so.preload
        if [[ -f /etc/ld.so.preload ]]; then
            sudo sed -i '/libclawguard/d' /etc/ld.so.preload
            [[ -s /etc/ld.so.preload ]] || sudo rm -f /etc/ld.so.preload
            log "  Cleaned /etc/ld.so.preload"
        fi
        # Remove from systemd service Environment if still present
        if [[ -f /etc/systemd/system/clawtower.service ]]; then
            sudo sed -i '/LD_PRELOAD.*libclawguard/d' /etc/systemd/system/clawtower.service 2>/dev/null || true
        fi
        REMOVED+=("LD_PRELOAD guard")
    else
        SKIPPED+=("LD_PRELOAD guard")
    fi
else
    info "LD_PRELOAD guard not found"
fi

# ══════════════════════════════════════════════════════════════════════════════
# MODULE: Capability Restrictions
# ══════════════════════════════════════════════════════════════════════════════
echo ""
info "── Capability Restrictions ──"
if [[ -f /etc/security/capability.conf ]] && grep -qE 'cap_linux_immutable|cap_sys_ptrace|cap_sys_module' /etc/security/capability.conf 2>/dev/null; then
    info "capability.conf drops dangerous caps from targeted users at login."
    if ask "Remove capability restrictions?"; then
        sudo sed -i '/cap_linux_immutable\|cap_sys_ptrace\|cap_sys_module/d' /etc/security/capability.conf
        # Remove file if empty (only comments/whitespace left)
        if ! grep -qE '^[^#]' /etc/security/capability.conf 2>/dev/null; then
            sudo rm -f /etc/security/capability.conf
            log "  Removed empty capability.conf"
        else
            log "  Cleaned ClawTower entries from capability.conf"
        fi
        # Remove pam_cap from auth stack
        if grep -q 'pam_cap.so' /etc/pam.d/common-auth 2>/dev/null; then
            sudo sed -i '/pam_cap.so/d' /etc/pam.d/common-auth
            log "  Removed pam_cap from PAM auth stack"
        fi
        REMOVED+=("capability restrictions")
    else
        SKIPPED+=("capability restrictions")
    fi
else
    info "No ClawTower capability restrictions found"
fi

# ══════════════════════════════════════════════════════════════════════════════
# MODULE: Kernel Hardening (sysctl)
# ══════════════════════════════════════════════════════════════════════════════
echo ""
info "── Kernel Hardening (sysctl) ──"
if [[ -f /etc/sysctl.d/99-clawtower.conf ]]; then
    info "ClawTower set: $(cat /etc/sysctl.d/99-clawtower.conf | grep -v '^#' | grep -v '^$' | tr '\n' ', ')"
    if ask "Remove kernel hardening sysctl?"; then
        sudo rm -f /etc/sysctl.d/99-clawtower.conf
        # Restore defaults where possible at runtime
        sudo sysctl -w kernel.yama.ptrace_scope=1 2>/dev/null \
            && log "  Restored ptrace_scope=1" \
            || warn "  Could not restore ptrace_scope at runtime"
        # modules_disabled=1 cannot be undone without reboot
        CURRENT_MODDISABLED=$(cat /proc/sys/kernel/modules_disabled 2>/dev/null || echo "0")
        if [[ "$CURRENT_MODDISABLED" == "1" ]]; then
            REBOOT_REASONS+=("kernel.modules_disabled=1 cannot be undone without reboot")
        fi
        REMOVED+=("kernel hardening sysctl")
    else
        SKIPPED+=("kernel hardening sysctl")
    fi
else
    info "No ClawTower sysctl config found"
fi

# ══════════════════════════════════════════════════════════════════════════════
# MODULE: Auditd Rules
# ══════════════════════════════════════════════════════════════════════════════
echo ""
info "── Auditd Rules ──"
AUDIT_RULES_FILE="/etc/audit/rules.d/clawtower.rules"
AUDIT_LOCKED=false
if command -v auditctl &>/dev/null; then
    AUDIT_ENABLED=$(auditctl -s 2>/dev/null | grep -oP 'enabled\s+\K\d+' || echo "0")
    [[ "$AUDIT_ENABLED" == "2" ]] && AUDIT_LOCKED=true
fi

if [[ -f "$AUDIT_RULES_FILE" ]] || (command -v auditctl &>/dev/null && auditctl -l 2>/dev/null | grep -q "clawtower"); then
    RULE_COUNT=$(auditctl -l 2>/dev/null | grep -c "clawtower" || echo "?")
    info "Found $RULE_COUNT active clawtower audit rules"
    if $AUDIT_LOCKED; then
        warn "Audit rules are LOCKED (enabled=2) — rules file will be deleted but"
        warn "active rules won't clear until reboot."
    fi
    if ask "Remove ClawTower auditd rules?"; then
        sudo rm -f "$AUDIT_RULES_FILE"
        log "  Deleted $AUDIT_RULES_FILE"
        if ! $AUDIT_LOCKED; then
            # Try to reload without clawtower rules
            sudo augenrules --load 2>/dev/null || true
            # Also try to unlock audit (set to enabled=1, mutable)
            sudo auditctl -e 1 2>/dev/null \
                && log "  Audit rules unlocked (enabled=1)" \
                || warn "  Could not unlock audit rules"
            # Delete runtime rules
            for key in clawtower_exec clawtower_tamper clawtower_privesc clawtower_net clawtower_perm clawtower_module clawtower_cred_read clawtower-tamper clawtower-config; do
                sudo auditctl -D -k "$key" 2>/dev/null || true
            done
            log "  Cleared runtime audit rules"
        else
            REBOOT_REASONS+=("audit rules locked — will clear on reboot")
        fi
        REMOVED+=("auditd rules")
    else
        SKIPPED+=("auditd rules")
    fi
else
    info "No ClawTower audit rules found"
fi

# ══════════════════════════════════════════════════════════════════════════════
# MODULE: iptables / nftables Firewall Rules
# ══════════════════════════════════════════════════════════════════════════════
echo ""
info "── Firewall Rules (iptables/nftables) ──"
FW_FOUND=false

# Check nftables
if command -v nft &>/dev/null && nft list table inet clawtower &>/dev/null 2>&1; then
    FW_FOUND=true
    info "Found nftables table 'clawtower' (logs agent network activity)"
    if ask "Remove nftables clawtower table?"; then
        sudo nft delete table inet clawtower 2>/dev/null \
            && log "  Deleted nftables table inet clawtower" \
            || warn "  Failed to delete nftables table"
        REMOVED+=("nftables firewall rules")
    else
        SKIPPED+=("nftables firewall rules")
    fi
fi

# Check iptables
if command -v iptables &>/dev/null && iptables -L OUTPUT -n 2>/dev/null | grep -q "OPENCLAWTOWER_NET"; then
    FW_FOUND=true
    info "Found iptables OUTPUT rule with OPENCLAWTOWER_NET log prefix"
    if ask "Remove iptables logging rules?"; then
        # Find and remove all matching rules (may be multiple)
        while iptables -L OUTPUT --line-numbers -n 2>/dev/null | grep -q "OPENCLAWTOWER_NET"; do
            LINENUM=$(iptables -L OUTPUT --line-numbers -n 2>/dev/null | grep "OPENCLAWTOWER_NET" | head -1 | awk '{print $1}')
            sudo iptables -D OUTPUT "$LINENUM" 2>/dev/null || break
        done
        log "  Removed iptables rules"
        REMOVED+=("iptables firewall rules")
    else
        SKIPPED+=("iptables firewall rules")
    fi
fi

if ! $FW_FOUND; then
    info "No ClawTower firewall rules found"
fi

# ══════════════════════════════════════════════════════════════════════════════
# MODULE: Falco
# ══════════════════════════════════════════════════════════════════════════════
echo ""
info "── Falco (runtime security) ──"
if command -v falco &>/dev/null || [[ -f /etc/falco/rules.d/openclaw_rules.yaml ]]; then
    info "Falco is installed with ClawTower custom rules."
    if ask "Remove ClawTower Falco rules? (Falco itself will remain installed)"; then
        sudo rm -f /etc/falco/rules.d/openclaw_rules.yaml
        log "  Removed ClawTower Falco rules"
        # Restart falco to pick up rule removal
        sudo systemctl restart falco 2>/dev/null || true
        REMOVED+=("Falco custom rules")
    else
        SKIPPED+=("Falco rules")
    fi
    if command -v falco &>/dev/null; then
        if ask "Also completely uninstall Falco? (not just rules)" "n"; then
            sudo systemctl stop falco 2>/dev/null || true
            sudo systemctl disable falco 2>/dev/null || true
            if dpkg -l falco &>/dev/null 2>&1; then
                sudo apt-get remove -y falco 2>/dev/null || true
            else
                # Tarball install — remove manually
                sudo rm -f /usr/bin/falco /usr/local/bin/falco
                sudo rm -rf /etc/falco /var/log/falco
            fi
            log "  Uninstalled Falco"
            REMOVED+=("Falco (full uninstall)")
        else
            SKIPPED+=("Falco binary")
        fi
    fi
else
    info "Falco not found"
fi

# ══════════════════════════════════════════════════════════════════════════════
# MODULE: Samhain (File Integrity Monitoring)
# ══════════════════════════════════════════════════════════════════════════════
echo ""
info "── Samhain (file integrity monitoring) ──"
if command -v samhain &>/dev/null || [[ -f /etc/samhainrc ]]; then
    info "Samhain FIM is installed (monitors file changes for tampering)."
    if ask "Remove Samhain? (compiled from source)" "n"; then
        sudo systemctl stop samhain 2>/dev/null || true
        sudo systemctl disable samhain 2>/dev/null || true
        sudo rm -f /usr/local/sbin/samhain /usr/local/bin/samhain
        sudo rm -f /etc/samhainrc
        sudo rm -rf /var/lib/samhain /var/log/samhain
        sudo rm -f /etc/systemd/system/samhain.service
        sudo systemctl daemon-reload
        log "  Removed Samhain"
        REMOVED+=("Samhain FIM")
    else
        SKIPPED+=("Samhain")
    fi
else
    info "Samhain not found"
fi

# ══════════════════════════════════════════════════════════════════════════════
# MODULE: Disabled Services (rpcbind, docker group)
# ══════════════════════════════════════════════════════════════════════════════
echo ""
info "── Service Restrictions ──"

# rpcbind
if systemctl is-masked rpcbind 2>/dev/null; then
    info "rpcbind is masked (disabled by ClawTower install)"
    if ask "Unmask and re-enable rpcbind?" "n"; then
        sudo systemctl unmask rpcbind rpcbind.socket 2>/dev/null || true
        sudo systemctl enable rpcbind rpcbind.socket 2>/dev/null || true
        sudo systemctl start rpcbind 2>/dev/null || true
        log "  Unmasked and started rpcbind"
        REMOVED+=("rpcbind mask")
    else
        SKIPPED+=("rpcbind (stays masked)")
    fi
else
    info "rpcbind not masked"
fi

# Docker group
for user in "${TARGET_USERS[@]}"; do
    if id "$user" &>/dev/null && getent group docker &>/dev/null; then
        if ! id -nG "$user" 2>/dev/null | grep -qw docker; then
            info "$user is NOT in docker group (may have been removed by ClawTower)"
            if ask "Add $user back to docker group?" "n"; then
                sudo usermod -aG docker "$user"
                log "  Added $user to docker group"
                REMOVED+=("docker group restriction for $user")
            else
                SKIPPED+=("docker group for $user")
            fi
        fi
    fi
done

# ══════════════════════════════════════════════════════════════════════════════
# MODULE: Systemd Service File
# ══════════════════════════════════════════════════════════════════════════════
echo ""
info "── Systemd Service ──"
if [[ -f /etc/systemd/system/clawtower.service ]]; then
    sudo rm -f /etc/systemd/system/clawtower.service
    sudo systemctl daemon-reload
    log "  Removed clawtower.service"
    REMOVED+=("systemd service file")
fi

# ══════════════════════════════════════════════════════════════════════════════
# MODULE: Tray Autostart
# ══════════════════════════════════════════════════════════════════════════════
echo ""
info "── Tray Autostart ──"
CALLING_USER="${SUDO_USER:-$USER}"
CALLING_HOME=$(eval echo "~$CALLING_USER")
TRAY_DESKTOP="$CALLING_HOME/.config/autostart/clawtower-tray.desktop"
if [[ -f "$TRAY_DESKTOP" ]]; then
    sudo rm -f "$TRAY_DESKTOP"
    log "  Removed tray autostart"
    REMOVED+=("tray autostart")
fi

# ══════════════════════════════════════════════════════════════════════════════
# MODULE: Binaries
# ══════════════════════════════════════════════════════════════════════════════
echo ""
info "── Binaries ──"
for bin in /usr/local/bin/clawtower /usr/local/bin/clawsudo /usr/local/bin/clawtower-tray; do
    if [[ -f "$bin" ]]; then
        sudo chattr -ia "$bin" 2>/dev/null || true
        sudo rm -f "$bin" && log "  Removed $bin" || warn "  Could not remove $bin"
    fi
done
REMOVED+=("binaries")

# ══════════════════════════════════════════════════════════════════════════════
# MODULE: Quarantined Files
# ══════════════════════════════════════════════════════════════════════════════
if [[ -d /etc/clawtower/quarantine ]] && [[ -n "$(ls -A /etc/clawtower/quarantine 2>/dev/null)" ]]; then
    echo ""
    info "── Quarantined Files ──"
    QCOUNT=$(find /etc/clawtower/quarantine -type f 2>/dev/null | wc -l)
    warn "$QCOUNT quarantined file(s) in /etc/clawtower/quarantine/"
    ls -la /etc/clawtower/quarantine/ 2>/dev/null | head -10 || true
    warn "These are files ClawTower intercepted as threats."
    if ask "Delete quarantined files? (copy them out first if needed)" "n"; then
        log "  Deleting quarantine..."
    else
        info "  Leaving quarantine in place — move files before removing /etc/clawtower/"
        SKIPPED+=("quarantined files")
    fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# MODULE: Config Directory
# ══════════════════════════════════════════════════════════════════════════════
echo ""
info "── Configuration ──"
if [[ -d /etc/clawtower ]]; then
    sudo find /etc/clawtower -type f -exec chattr -ia {} \; 2>/dev/null || true
    sudo rm -rf /etc/clawtower
    log "  Removed /etc/clawtower/"
    REMOVED+=("config directory")
fi

# ══════════════════════════════════════════════════════════════════════════════
# MODULE: Data & Logs
# ══════════════════════════════════════════════════════════════════════════════
echo ""
info "── Data & Logs ──"
if $KEEP_DATA; then
    info "Keeping logs and audit data at /var/log/clawtower/ (--keep-data)"
    SKIPPED+=("logs (--keep-data)")
else
    if [[ -d /var/log/clawtower ]]; then
        if ask "Delete all ClawTower logs and audit data?"; then
            sudo rm -rf /var/log/clawtower
            log "  Removed /var/log/clawtower/"
            REMOVED+=("logs and audit data")
        else
            SKIPPED+=("logs")
        fi
    fi
fi
sudo rm -rf /var/run/clawtower 2>/dev/null || true

# ══════════════════════════════════════════════════════════════════════════════
# MODULE: System User
# ══════════════════════════════════════════════════════════════════════════════
echo ""
info "── System User ──"
if id -u clawtower &>/dev/null; then
    if ask "Remove clawtower system user?"; then
        sudo userdel clawtower 2>/dev/null || true
        log "  Removed clawtower user"
        REMOVED+=("system user")
    else
        SKIPPED+=("system user")
    fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ✅ ClawTower uninstall complete                             ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"

if [[ ${#REMOVED[@]} -gt 0 ]]; then
    echo -e "${GREEN}║                                                              ║${NC}"
    echo -e "${GREEN}║  Removed:                                                    ║${NC}"
    for item in "${REMOVED[@]}"; do
        printf "${GREEN}║    • %-54s ║${NC}\n" "$item"
    done
fi

if [[ ${#SKIPPED[@]} -gt 0 ]]; then
    echo -e "${YELLOW}║                                                              ║${NC}"
    echo -e "${YELLOW}║  Skipped (kept):                                             ║${NC}"
    for item in "${SKIPPED[@]}"; do
        printf "${YELLOW}║    • %-54s ║${NC}\n" "$item"
    done
fi

if [[ ${#REBOOT_REASONS[@]} -gt 0 ]]; then
    echo -e "${RED}║                                                              ║${NC}"
    echo -e "${RED}║  ⚠️  Reboot recommended:                                     ║${NC}"
    for reason in "${REBOOT_REASONS[@]}"; do
        printf "${RED}║    • %-54s ║${NC}\n" "$reason"
    done
fi

echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Clean up uninstall log on success (unless keeping data)
if ! $KEEP_DATA; then
    rm -f "$UNINSTALL_LOG" 2>/dev/null || true
fi
