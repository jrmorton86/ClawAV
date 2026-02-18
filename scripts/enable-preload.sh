#!/bin/bash
# Install libclawtower.so and configure LD_PRELOAD for ClawTower
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LIB_DIR="/usr/local/lib/clawtower"
POLICY_DIR="/etc/clawtower"
POLICY_FILE="$POLICY_DIR/preload-policy.json"
SO_FILE="$LIB_DIR/libclawtower.so"
SERVICE_FILE="/etc/systemd/system/clawtower.service"

[[ $EUID -eq 0 ]] || { echo "[ERROR] Must run as root"; exit 1; }

# chattr wrapper: falls back to systemd-run when CAP_LINUX_IMMUTABLE is missing
do_chattr() {
    local flag="$1" path="$2"
    if chattr "$flag" "$path" 2>/dev/null; then return 0; fi
    systemd-run --wait --collect --quiet chattr "$flag" "$path" 2>/dev/null
}

# ── 1. Install shared library ────────────────────────────────────────────────
echo "[PRELOAD] Installing libclawtower.so..."
mkdir -p "$LIB_DIR"
cp "$PROJECT_DIR/libclawtower.so" "$SO_FILE"
chmod 755 "$SO_FILE"

# ── 2. Create default policy ─────────────────────────────────────────────────
echo "[PRELOAD] Creating default preload policy..."
mkdir -p "$POLICY_DIR"
mkdir -p /var/log/clawtower

if [ ! -f "$POLICY_FILE" ]; then
    cat > "$POLICY_FILE" <<'POLICY'
{
  "deny_exec": ["bash -c", "sh -c"],
  "deny_paths_write": ["/etc/shadow", "/etc/passwd", "/etc/hosts", "/etc/clawtower"],
  "deny_connect": [],
  "log_file": "/var/log/clawtower/preload.log",
  "enabled": true
}
POLICY
    chmod 644 "$POLICY_FILE"
    echo "[PRELOAD] Default policy created at $POLICY_FILE"
else
    echo "[PRELOAD] Policy already exists, skipping"
fi

# ── 3. Add LD_PRELOAD to systemd service environment ─────────────────────────
echo "[PRELOAD] Configuring systemd environment..."
if [ -f "$SERVICE_FILE" ]; then
    # Remove immutable flag temporarily if set
    do_chattr -i "$SERVICE_FILE" || true

    if ! grep -q "LD_PRELOAD" "$SERVICE_FILE"; then
        # Add Environment line after [Service] section
        sed -i '/^\[Service\]/a Environment=LD_PRELOAD=/usr/local/lib/clawtower/libclawtower.so' "$SERVICE_FILE"
        echo "[PRELOAD] Added LD_PRELOAD to systemd service"
    else
        echo "[PRELOAD] LD_PRELOAD already configured in service"
    fi

    # Restore immutable flag
    do_chattr +i "$SERVICE_FILE" || true
    systemctl daemon-reload
else
    echo "[PRELOAD] Service file not found — LD_PRELOAD must be configured manually"
fi

# ── 4. Make .so immutable ─────────────────────────────────────────────────────
echo "[PRELOAD] Setting immutable flag on libclawtower.so..."
do_chattr +i "$SO_FILE" || echo "[WARN] chattr +i failed (filesystem may not support it)"

echo "[PRELOAD] Installation complete!"
echo "  Library: $SO_FILE"
echo "  Policy:  $POLICY_FILE"
echo "  Log:     /var/log/clawtower/preload.log"
