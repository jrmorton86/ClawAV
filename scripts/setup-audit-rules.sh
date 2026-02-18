#!/bin/bash
set -euo pipefail

RULES_FILE="/etc/audit/rules.d/clawtower.rules"
WATCHED_USER="${CLAWTOWER_WATCHED_USER:-${OPENCLAW_USER:-openclaw}}"
WATCHED_UID=$(id -u "$WATCHED_USER" 2>/dev/null || echo "")
WATCHED_HOME=$(getent passwd "$WATCHED_USER" 2>/dev/null | cut -d: -f6)

if [ -z "$WATCHED_UID" ]; then
	echo "ERROR: User '$WATCHED_USER' not found"
	exit 1
fi

if [ -z "$WATCHED_HOME" ]; then
	WATCHED_HOME="/home/$WATCHED_USER"
fi

cat > "$RULES_FILE" << EOF
# ClawTower audit rules — comprehensive monitoring

# === Tamper detection ===
-w /usr/local/bin/clawtower -p a -k clawtower-tamper
-w /etc/clawtower/ -p wa -k clawtower-config
-w /etc/systemd/system/clawtower.service -p wa -k clawtower-tamper
-w /etc/sudoers.d/clawtower-deny -p wa -k clawtower-tamper
-w /etc/apparmor.d/clawtower.deny-agent -p wa -k clawtower-tamper
-w /usr/bin/chattr -p x -k clawtower-tamper

# === Credential file read monitoring (Flag 1 — EXFIL) ===
-w $WATCHED_HOME/.openclaw/agents/main/agent/auth-profiles.json -p r -k clawtower_cred_read
-w $WATCHED_HOME/.aws/credentials -p r -k clawtower_cred_read
-w $WATCHED_HOME/.aws/config -p r -k clawtower_cred_read
-w $WATCHED_HOME/.ssh/id_ed25519 -p r -k clawtower_cred_read
-w $WATCHED_HOME/.ssh/id_rsa -p r -k clawtower_cred_read
-w $WATCHED_HOME/.openclaw/gateway.yaml -p r -k clawtower_cred_read

# === System credential file monitoring (Flag 7 — RUNTIME ABUSE) ===
-w /etc/shadow -p r -k clawtower_cred_read
-w /etc/gshadow -p r -k clawtower_cred_read
-w /etc/sudoers -p r -k clawtower_cred_read
-w /etc/sudoers.d/ -p r -k clawtower_cred_read

# === OpenClaw session log monitoring ===
-w $WATCHED_HOME/.openclaw/agents/main/sessions/ -p r -k openclaw_session_read

# === Network connect() monitoring (Flag 6 — ESCAPE) ===
# Monitor ALL connect() attempts — failed connects (ECONNREFUSED) are just as suspicious
-a always,exit -F arch=b64 -S connect -F uid=$WATCHED_UID -k clawtower_net_connect

# === sendfile/copy_file_range monitoring (catches shutil.copyfile bypass) ===
-a always,exit -F arch=b64 -S sendfile -F uid=$WATCHED_UID -F success=1 -k clawtower_cred_read
-a always,exit -F arch=b64 -S copy_file_range -F uid=$WATCHED_UID -F success=1 -k clawtower_cred_read
EOF

# Reload audit rules
augenrules --load 2>/dev/null || auditctl -R "$RULES_FILE"

echo "Audit rules installed and loaded"
