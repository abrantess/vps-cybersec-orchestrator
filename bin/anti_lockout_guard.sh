#!/usr/bin/env bash
# =============================================================================
# VPS CyberSec Orchestrator — Anti-Lockout Dead-Man's Switch Guard
# Ensures administrator never loses SSH connectivity during network/firewall changes.
# =============================================================================
set -euo pipefail

ACTION="${1:-help}"
TIMEOUT_MINUTES="${2:-5}"
BACKUP_DIR="/tmp/vps_anti_lockout_backup"
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
    mkdir -p "$BACKUP_DIR"
    
    # Backup current firewall rules and SSH configuration
    if command -v iptables-save >/dev/null 2>&1; then
        iptables-save > "$BACKUP_DIR/iptables.rules" || true
    fi
    if command -v ip6tables-save >/dev/null 2>&1; then
        ip6tables-save > "$BACKUP_DIR/ip6tables.rules" || true
    fi
    if command -v ufw >/dev/null 2>&1; then
        ufw status verbose > "$BACKUP_DIR/ufw.status" || true
    fi
    if [[ -d /etc/ssh ]]; then
        cp -r /etc/ssh "$BACKUP_DIR/ssh_backup" || true
    fi

    # Create emergency rollback executable
    cat << 'EOF' > "$ROLLBACK_SCRIPT"
#!/usr/bin/env bash
echo "[!] EMERGENCY DEAD-MAN'S SWITCH TRIGGERED: Reverting firewall and restoring SSH..."
if command -v ufw >/dev/null 2>&1; then
    ufw --force disable || true
fi
if command -v iptables >/dev/null 2>&1; then
    iptables -P INPUT ACCEPT || true
    iptables -P FORWARD ACCEPT || true
    iptables -P OUTPUT ACCEPT || true
    iptables -F || true
fi
if [[ -d /tmp/vps_anti_lockout_backup/ssh_backup ]]; then
    cp -r /tmp/vps_anti_lockout_backup/ssh_backup/* /etc/ssh/ || true
    systemctl reload ssh || systemctl restart ssh || service ssh restart || true
fi
echo "[+] Emergency rollback executed. Access restored."
EOF
    chmod 700 "$ROLLBACK_SCRIPT"
}

arm_switch() {
    create_rollback_script
    echo "[*] Arming Anti-Lockout Dead-Man's Switch for $TIMEOUT_MINUTES minute(s)..."
    
    if command -v systemd-run >/dev/null 2>&1 && systemctl is-active --quiet dbus 2>/dev/null; then
        systemd-run --on-active="${TIMEOUT_MINUTES}m" --unit="$TIMER_UNIT" "$ROLLBACK_SCRIPT" >/dev/null 2>&1
        echo "[+] Timer '$TIMER_UNIT' armed via systemd. Rollback will trigger in ${TIMEOUT_MINUTES}m unless confirmed."
    else
        # Fallback to detached background sleep process
        (
            sleep $((TIMEOUT_MINUTES * 60))
            if [[ -f "$BACKUP_DIR/armed.lock" ]]; then
                bash "$ROLLBACK_SCRIPT"
                rm -f "$BACKUP_DIR/armed.lock"
            fi
        ) >/dev/null 2>&1 &
        echo $! > "$BACKUP_DIR/timer.pid"
        touch "$BACKUP_DIR/armed.lock"
        echo "[+] Background timer PID $(cat "$BACKUP_DIR/timer.pid") armed. Rollback will trigger in ${TIMEOUT_MINUTES}m unless confirmed."
    fi
}

disarm_switch() {
    echo "[*] Disarming Anti-Lockout Dead-Man's Switch..."
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop "$TIMER_UNIT.timer" "$TIMER_UNIT.service" 2>/dev/null || true
        systemctl reset-failed "$TIMER_UNIT.timer" "$TIMER_UNIT.service" 2>/dev/null || true
    fi
    if [[ -f "$BACKUP_DIR/timer.pid" ]]; then
        kill -9 "$(cat "$BACKUP_DIR/timer.pid")" 2>/dev/null || true
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
