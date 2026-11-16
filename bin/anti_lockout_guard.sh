#!/usr/bin/env bash
# =============================================================================
# VPS CyberSec Orchestrator — Anti-Lockout Dead-Man's Switch Guard (v1.0.1)
# Ensures administrator never loses SSH connectivity during network/firewall changes.
# Security: Backups are stored in /root/.vps_anti_lockout_backup (0700).
# =============================================================================
set -euo pipefail

ACTION="${1:-help}"
TIMEOUT_MINUTES="${2:-5}"
BACKUP_DIR="/root/.vps_anti_lockout_backup"
ROLLBACK_SCRIPT="/usr/local/sbin/vps-emergency-rollback.sh"
TIMER_UNIT="vps-anti-lockout-rollback"

usage() {
    echo "Usage: $0 {arm [timeout_mins]|disarm|rollback|status}"
    echo "  arm [N]  : Sets a dead-man's switch to auto-rollback firewall in N minutes (default: 5)"
    echo "  disarm   : Confirms connectivity and cancels the pending rollback timer"
    echo "  rollback : Immediately executes emergency rollback of firewall and SSH"
    echo "  status   : Checks if a rollback timer is currently pending"
    exit 1
}

create_rollback_script() {
    install -d -m 700 "$BACKUP_DIR"
    
    # 1. Atomic backup of firewall rules
    if command -v iptables-save >/dev/null 2>&1; then
        iptables-save > "$BACKUP_DIR/iptables.rules" 2>/dev/null || true
    fi
    if command -v ip6tables-save >/dev/null 2>&1; then
        ip6tables-save > "$BACKUP_DIR/ip6tables.rules" 2>/dev/null || true
    fi
    if command -v ufw >/dev/null 2>&1; then
        ufw status verbose > "$BACKUP_DIR/ufw.status" 2>/dev/null || true
    fi

    # 2. Secure backup of SSH configuration with permissions preserved (mode 0700/0600)
    if [[ -d /etc/ssh ]]; then
        rm -rf "$BACKUP_DIR/ssh_backup"
        cp -a /etc/ssh "$BACKUP_DIR/ssh_backup"
    fi

    # 3. Create emergency rollback executable with explicit drop-in cleanup
    cat << 'EOF' > "$ROLLBACK_SCRIPT"
#!/usr/bin/env bash
echo "[!] EMERGENCY DEAD-MAN'S SWITCH TRIGGERED: Reverting firewall and restoring SSH..."

# Revert UFW
if command -v ufw >/dev/null 2>&1; then
    ufw --force disable >/dev/null 2>&1 || true
fi

# Revert Netfilter / iptables to permissive state
if command -v iptables >/dev/null 2>&1; then
    iptables -P INPUT ACCEPT 2>/dev/null || true
    iptables -P FORWARD ACCEPT 2>/dev/null || true
    iptables -P OUTPUT ACCEPT 2>/dev/null || true
    iptables -F 2>/dev/null || true
fi

# Clean up added hardening drop-ins before restore to prevent persistent lockout
rm -f /etc/ssh/sshd_config.d/*hardening*.conf /etc/ssh/sshd_config.d/00-*.conf 2>/dev/null || true

# Restore original SSH configuration
if [[ -d /root/.vps_anti_lockout_backup/ssh_backup ]]; then
    cp -a /root/.vps_anti_lockout_backup/ssh_backup/* /etc/ssh/ 2>/dev/null || true
fi

# Multi-distro SSH daemon reload / restart
if command -v systemctl >/dev/null 2>&1; then
    systemctl reload ssh 2>/dev/null || systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
elif command -v service >/dev/null 2>&1; then
    service ssh restart 2>/dev/null || service sshd restart 2>/dev/null || true
elif command -v rc-service >/dev/null 2>&1; then
    rc-service sshd restart 2>/dev/null || true
fi

# Restart Docker network if iptables was flushed
if command -v docker >/dev/null 2>&1 && command -v systemctl >/dev/null 2>&1; then
    systemctl restart docker 2>/dev/null || true
fi

echo "[+] Emergency rollback executed. Access restored."
EOF
    chmod 700 "$ROLLBACK_SCRIPT"
}

arm_switch() {
    if ! [[ "$TIMEOUT_MINUTES" =~ ^[0-9]+$ ]] || [[ "$TIMEOUT_MINUTES" -lt 1 ]]; then
        echo "[-] Error: Timeout must be a positive integer in minutes. Got: $TIMEOUT_MINUTES"
        exit 1
    fi

    create_rollback_script
    echo "[*] Arming Anti-Lockout Dead-Man's Switch for $TIMEOUT_MINUTES minute(s)..."
    
    if command -v systemd-run >/dev/null 2>&1 && systemctl is-active --quiet dbus 2>/dev/null; then
        if systemd-run --on-active="${TIMEOUT_MINUTES}m" --unit="$TIMER_UNIT" "$ROLLBACK_SCRIPT" >/dev/null 2>&1; then
            echo "[+] Timer '$TIMER_UNIT' successfully armed via systemd."
            echo "[+] Rollback will trigger in ${TIMEOUT_MINUTES}m unless explicitly disarmed."
            return 0
        fi
    fi

    # Fallback to detached background subshell process
    (
        sleep $((TIMEOUT_MINUTES * 60))
        if [[ -f "$BACKUP_DIR/armed.lock" ]]; then
            bash "$ROLLBACK_SCRIPT"
            rm -f "$BACKUP_DIR/armed.lock"
        fi
    ) >/dev/null 2>&1 &
    local pid=$!
    echo "$pid" > "$BACKUP_DIR/timer.pid"
    touch "$BACKUP_DIR/armed.lock"
    echo "[+] Background timer PID $pid armed. Rollback will trigger in ${TIMEOUT_MINUTES}m unless confirmed."
}

disarm_switch() {
    echo "[*] Disarming Anti-Lockout Dead-Man's Switch..."
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop "$TIMER_UNIT.timer" "$TIMER_UNIT.service" 2>/dev/null || true
        systemctl reset-failed "$TIMER_UNIT.timer" "$TIMER_UNIT.service" 2>/dev/null || true
    fi
    if [[ -f "$BACKUP_DIR/timer.pid" ]]; then
        local pid
        pid=$(cat "$BACKUP_DIR/timer.pid" 2>/dev/null || true)
        if [[ -n "$pid" ]]; then
            kill -9 "$pid" 2>/dev/null || true
        fi
        rm -f "$BACKUP_DIR/timer.pid"
    fi
    rm -f "$BACKUP_DIR/armed.lock" "$ROLLBACK_SCRIPT"
    echo "[+] Dead-Man's Switch disarmed. Current configuration confirmed safe."
}

check_status() {
    local armed=0
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active --quiet "$TIMER_UNIT.timer" 2>/dev/null; then
            armed=1
        fi
    fi
    if [[ -f "$BACKUP_DIR/armed.lock" ]]; then
        armed=1
    fi

    if [[ $armed -eq 1 ]]; then
        echo "[!] WARNING: Anti-Lockout Dead-Man's Switch is currently ARMED."
    else
        echo "[+] Anti-Lockout Dead-Man's Switch is inactive (DISARMED)."
    fi
}

case "$ACTION" in
    arm) arm_switch ;;
    disarm) disarm_switch ;;
    rollback) bash "$ROLLBACK_SCRIPT" ;;
    status) check_status ;;
    *) usage ;;
esac
