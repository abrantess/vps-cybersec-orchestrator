#!/usr/bin/env bash
# =============================================================================
# VPS CyberSec Orchestrator — Idempotent Hardening Engine (v1.0.1)
# CIS Linux Benchmark & DevSecOps Compliance Automator
# Security: Includes dynamic SSH port detection and Dead-Man's Switch protection.
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
echo "🛡️  VPS CyberSec Orchestrator — Idempotent Hardening Engine (v1.0.1)"
echo "Dry-Run Mode : $([[ $DRY_RUN -eq 1 ]] && echo 'ENABLED (Simulation Only)' || echo 'DISABLED (Active Mutation)')"
echo "========================================================================"

if [[ $DRY_RUN -eq 0 && $CONFIRM -eq 0 ]]; then
    echo "🛑 [SAFETY GATE]: Active mutations require explicit confirmation."
    echo "To simulate changes without writing to disk: $0 --dry-run"
    echo "To apply changes with safety dead-man's switch: $0 --confirm"
    exit 1
fi

if [[ $EUID -ne 0 && $DRY_RUN -eq 0 ]]; then
    echo "[-] Error: Root privileges are required to apply system hardening."
    exit 1
fi

# Detect active SSH port dynamically
ACTIVE_SSH_PORT="$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}' || echo '22')"
ACTIVE_SSH_PORT="${ACTIVE_SSH_PORT:-22}"

# Pre-flight check: ensure at least one authorized_keys file has content before disabling password auth
HAS_AUTH_KEYS=0
if [[ -s /root/.ssh/authorized_keys ]]; then
    HAS_AUTH_KEYS=1
fi
for user_home in /home/*; do
    if [[ -s "$user_home/.ssh/authorized_keys" ]]; then
        HAS_AUTH_KEYS=1
        break
    fi
done

if [[ $HAS_AUTH_KEYS -eq 0 && $DRY_RUN -eq 0 ]]; then
    echo "⚠️  [PRE-FLIGHT WARNING]: No populated authorized_keys file found in /root or /home/*."
    echo "    Disabling PasswordAuthentication without public keys will lock you out!"
    echo "    Please add your SSH public key to ~/.ssh/authorized_keys before proceeding."
    exit 1
fi

if [[ $DRY_RUN -eq 0 ]]; then
    if [[ ! -f "$GUARD_SCRIPT" ]]; then
        echo "[-] Error: Anti-lockout guard script not found at $GUARD_SCRIPT"
        exit 1
    fi
    echo "[!] Arming Anti-Lockout Dead-Man's Switch (5 minutes safety window)..."
    bash "$GUARD_SCRIPT" arm 5
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

# 2. OpenSSH Server Hardening (00- prefix ensures first-match-wins precedence over cloud-init drop-ins)
echo "[2/4] Applying OpenSSH Configuration Hardening (detected port: $ACTIVE_SSH_PORT)..."
SSHD_CONF="/etc/ssh/sshd_config.d/00-vps-hardening.conf"
SSHD_CONTENT="# CIS Linux 5.2 OpenSSH Daemon Hardening (First-Match-Wins Priority)
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
    
    # Neutralize conflicting PasswordAuthentication yes in cloud-init configs if present
    if [[ -f /etc/ssh/sshd_config.d/50-cloud-init.conf ]]; then
        sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config.d/50-cloud-init.conf 2>/dev/null || true
    fi

    if sshd -t; then
        if command -v systemctl >/dev/null 2>&1; then
            systemctl reload ssh 2>/dev/null || systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
        elif command -v service >/dev/null 2>&1; then
            service ssh restart 2>/dev/null || service sshd restart 2>/dev/null || true
        elif command -v rc-service >/dev/null 2>&1; then
            rc-service sshd restart 2>/dev/null || true
        fi
        echo " -> [OK] OpenSSH syntax validated and service reloaded."
    else
        echo " -> [ERROR] sshd syntax validation failed! Reverting drop-in..."
        rm -f "$SSHD_CONF"
        exit 1
    fi
fi

# 3. Host Firewall Hardening (UFW) with Dynamic SSH Port Detection
echo "[3/4] Enforcing Host Firewall Default-Deny Policy (SSH Port: $ACTIVE_SSH_PORT/tcp)..."
if command -v ufw >/dev/null 2>&1; then
    if [[ $DRY_RUN -eq 1 ]]; then
        echo " -> [DRY-RUN] Would configure UFW default deny incoming, limit $ACTIVE_SSH_PORT/tcp, allow 80/443."
    else
        ufw default deny incoming >/dev/null 2>&1
        ufw default allow outgoing >/dev/null 2>&1
        ufw limit "${ACTIVE_SSH_PORT}/tcp" comment 'SSH Rate Limited' >/dev/null 2>&1 || true
        ufw allow 80/tcp comment 'HTTP' >/dev/null 2>&1 || true
        ufw allow 443/tcp comment 'HTTPS' >/dev/null 2>&1 || true
        ufw --force enable >/dev/null 2>&1
        echo " -> [OK] UFW default-deny policy enabled with ${ACTIVE_SSH_PORT}/tcp protected."
    fi
fi

# 4. Docker Daemon Hardening (Safe Merge for live-restore)
echo "[4/4] Auditing Docker Daemon Configuration (live-restore)..."
DOCKER_DAEMON="/etc/docker/daemon.json"
if command -v docker >/dev/null 2>&1 && [[ -d /etc/docker ]]; then
    if [[ $DRY_RUN -eq 1 ]]; then
        echo " -> [DRY-RUN] Would ensure 'live-restore': true in $DOCKER_DAEMON without breaking existing keys."
    else
        python3 - "$DOCKER_DAEMON" << 'PYEOF'
import sys, json, pathlib
p = pathlib.Path(sys.argv[1])
data = {}
if p.exists() and p.stat().st_size > 0:
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        data = {}
if data.get("live-restore") is not True:
    data["live-restore"] = True
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(" -> [OK] Merged 'live-restore': true into daemon.json.")
else:
    print(" -> [OK] Docker daemon.json already configured with live-restore.")
PYEOF
        if command -v systemctl >/dev/null 2>&1; then
            systemctl reload docker 2>/dev/null || true
        fi
    fi
fi

if [[ $DRY_RUN -eq 0 ]]; then
    echo "========================================================================"
    echo "🚨 IMPORTANT: Anti-Lockout Dead-Man's Switch is currently ARMED (5 min)."
    echo "   1. DO NOT CLOSE THIS CURRENT TERMINAL."
    echo "   2. Open a NEW terminal window and test SSH connectivity:"
    echo "      ssh -p ${ACTIVE_SSH_PORT} <user>@<host>"
    echo "   3. Once connectivity is verified, DISARM the safety switch by running:"
    echo "      sudo bash $GUARD_SCRIPT disarm"
    echo "   If connectivity fails, the server will automatically rollback in 5 min."
    echo "========================================================================"
fi
