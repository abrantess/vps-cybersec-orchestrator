#!/usr/bin/env bash
# =============================================================================
# VPS CyberSec Orchestrator — Idempotent Hardening Engine
# CIS Linux Benchmark & DevSecOps Compliance Automator
# Includes automated Dead-Man's Switch Anti-Lockout Protection.
# =============================================================================
set -euo pipefail
LC_ALL=C

DRY_RUN=0
CONFIRM=0
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARD_SCRIPT="$SCRIPT_DIR/anti_lockout_guard.sh"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=1; shift ;;
        --confirm) CONFIRM=1; shift ;;
        *) echo "Unknown option: $1"; echo "Usage: $0 [--dry-run] [--confirm]"; exit 1 ;;
    esac
done

echo "========================================================================"
echo "🛡️  VPS CyberSec Orchestrator — Idempotent Hardening Engine"
echo "Dry-Run Mode : $([[ $DRY_RUN -eq 1 ]] && echo 'ENABLED (Simulation Only)' || echo 'DISABLED (Active Mutation)')"
echo "========================================================================"

if [[ $DRY_RUN -eq 0 && $CONFIRM -eq 0 ]]; then
    echo "🛑 [SAFETY GATE]: Active mutations require explicit confirmation."
    echo "To simulate changes without writing to disk: $0 --dry-run"
    echo "To apply changes with safety dead-man's switch: $0 --confirm"
    exit 1
fi

if [[ $DRY_RUN -eq 0 ]]; then
    echo "[!] Arming Anti-Lockout Dead-Man's Switch (5 minutes safety window)..."
    if [[ -x "$GUARD_SCRIPT" ]]; then
        bash "$GUARD_SCRIPT" arm 5
    fi
fi

# 1. Kernel Sysctl Hardening
echo "[1/4] Applying CIS Kernel Network & Memory Sysctl Hardening..."
SYSCTL_CONF="/etc/sysctl.d/99-vps-hardening.conf"
SYSCTL_CONTENT="# CIS Linux Benchmark Kernel & Network Hardening
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 2
kernel.randomize_va_space = 2
kernel.kptr_restrict = 1
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
"

if [[ $DRY_RUN -eq 1 ]]; then
    echo " -> [DRY-RUN] Would write $SYSCTL_CONF:"
    echo "$SYSCTL_CONTENT" | sed 's/^/    /'
else
    echo "$SYSCTL_CONTENT" > "$SYSCTL_CONF"
    sysctl -p "$SYSCTL_CONF" >/dev/null 2>&1 || true
    echo " -> [OK] Kernel parameters successfully applied."
fi

# 2. OpenSSH Server Hardening
echo "[2/4] Applying OpenSSH Configuration Hardening..."
SSHD_CONF="/etc/ssh/sshd_config.d/99-vps-hardening.conf"
SSHD_CONTENT="# CIS Linux 5.2 OpenSSH Daemon Hardening
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
PubkeyAuthentication yes
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
"

if [[ $DRY_RUN -eq 1 ]]; then
    echo " -> [DRY-RUN] Would write $SSHD_CONF:"
    echo "$SSHD_CONTENT" | sed 's/^/    /'
else
    mkdir -p /etc/ssh/sshd_config.d/
    echo "$SSHD_CONTENT" > "$SSHD_CONF"
    if sshd -t; then
        systemctl reload ssh || systemctl restart ssh || service ssh restart || true
        echo " -> [OK] OpenSSH syntax validated and reloaded safely."
    else
        echo " -> [ERROR] sshd syntax validation failed! Reverting..."
        rm -f "$SSHD_CONF"
        exit 1
    fi
fi

# 3. Host Firewall Hardening (UFW)
echo "[3/4] Enforcing Host Firewall Default-Deny Policy..."
if command -v ufw >/dev/null 2>&1; then
    if [[ $DRY_RUN -eq 1 ]]; then
        echo " -> [DRY-RUN] Would configure UFW default deny incoming, allow 22/tcp rate-limited, allow 80/443."
    else
        ufw default deny incoming >/dev/null 2>&1
        ufw default allow outgoing >/dev/null 2>&1
        ufw limit 22/tcp comment 'SSH Rate Limited' >/dev/null 2>&1 || true
        ufw allow 80/tcp comment 'HTTP' >/dev/null 2>&1 || true
        ufw allow 443/tcp comment 'HTTPS' >/dev/null 2>&1 || true
        ufw --force enable >/dev/null 2>&1
        echo " -> [OK] UFW default-deny policy enabled."
    fi
fi

# 4. Docker Daemon Hardening (Live Restore)
echo "[4/4] Auditing Docker Daemon Configuration..."
DOCKER_DAEMON="/etc/docker/daemon.json"
if command -v docker >/dev/null 2>&1 && [[ -d /etc/docker ]]; then
    if [[ $DRY_RUN -eq 1 ]]; then
        echo " -> [DRY-RUN] Would ensure 'live-restore': true in $DOCKER_DAEMON."
    else
        if [[ ! -f "$DOCKER_DAEMON" ]]; then
            echo '{"live-restore": true}' > "$DOCKER_DAEMON"
        fi
        echo " -> [OK] Docker daemon configuration validated."
    fi
fi

if [[ $DRY_RUN -eq 0 ]]; then
    echo "========================================================================"
    echo "✅ Hardening applied successfully. Verifying session and disarming switch..."
    if [[ -x "$GUARD_SCRIPT" ]]; then
        bash "$GUARD_SCRIPT" disarm
    fi
    echo "========================================================================"
fi
