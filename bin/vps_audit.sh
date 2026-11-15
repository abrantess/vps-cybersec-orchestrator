#!/usr/bin/env bash
# =============================================================================
# VPS CyberSec Orchestrator — Non-Destructive Audit & Telemetry Collector
# Compatible with Ubuntu, Debian, Rocky, RHEL, Fedora, Alpine.
# Execution Protocol: Read-Only / Zero-Exploitation.
# =============================================================================
set -u
LC_ALL=C

OUTPUT_DIR="${1:-./audit_reports}"
mkdir -p "$OUTPUT_DIR"
TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
HOSTNAME="$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo 'unknown-host')"

echo "========================================================================"
echo "🛡️  VPS CyberSec Orchestrator — Autonomous Security Audit Collector"
echo "Target Host : $HOSTNAME"
echo "Timestamp   : $TIMESTAMP"
echo "Output Dir  : $OUTPUT_DIR"
echo "========================================================================"

# Temporary data directory
RAW_DIR="$(mktemp -d /tmp/vps_audit_raw_XXXXXX)"
trap 'rm -rf "$RAW_DIR"' EXIT

echo "[1/8] Collecting Host Architecture, OS Release and Kernel Baseline..."
uname -a > "$RAW_DIR/kernel_arch.txt"
cat /etc/os-release > "$RAW_DIR/os_release.txt" 2>/dev/null || true
uptime > "$RAW_DIR/uptime.txt"
cat /proc/sys/kernel/tainted > "$RAW_DIR/kernel_tainted.txt" 2>/dev/null || echo "0" > "$RAW_DIR/kernel_tainted.txt"

echo "[2/8] Auditing Critical Kernel Sysctl Parameters (CIS Linux 3.2)..."
sysctl -a 2>/dev/null | grep -E '^(net\.ipv4\.(ip_forward|tcp_syncookies|conf\.all\.(accept_redirects|send_redirects|rp_filter|log_martians|accept_source_route))|fs\.(suid_dumpable|protected_hardlinks|protected_symlinks)|kernel\.(randomize_va_space|kptr_restrict|dmesg_restrict|yama\.ptrace_scope))' | sort > "$RAW_DIR/sysctl_critical.txt" || true

echo "[3/8] Inspecting Network Interfaces, Routing and Open Sockets (ss)..."
ip -br addr > "$RAW_DIR/ip_addr.txt" 2>/dev/null || ifconfig > "$RAW_DIR/ip_addr.txt" 2>/dev/null || true
ip route > "$RAW_DIR/ip_route.txt" 2>/dev/null || route -n > "$RAW_DIR/ip_route.txt" 2>/dev/null || true
ss -tulnp > "$RAW_DIR/listening_sockets.txt" 2>/dev/null || netstat -tulnp > "$RAW_DIR/listening_sockets.txt" 2>/dev/null || true

echo "[4/8] Auditing Firewall Posture (UFW, Netfilter, Nftables)..."
if command -v ufw >/dev/null 2>&1; then
    ufw status verbose > "$RAW_DIR/ufw_status.txt" 2>/dev/null || true
fi
if command -v iptables-save >/dev/null 2>&1; then
    iptables-save > "$RAW_DIR/iptables_v4.txt" 2>/dev/null || true
fi
if command -v ip6tables-save >/dev/null 2>&1; then
    ip6tables-save > "$RAW_DIR/iptables_v6.txt" 2>/dev/null || true
fi
if command -v nft >/dev/null 2>&1; then
    nft list ruleset > "$RAW_DIR/nftables.txt" 2>/dev/null || true
fi

echo "[5/8] Auditing OpenSSH Server Configuration and Access Controls..."
if command -v sshd >/dev/null 2>&1; then
    sshd -T > "$RAW_DIR/sshd_active.txt" 2>/dev/null || true
fi
cut -d: -f1,3,6,7 /etc/passwd | awk -F: '$2 >= 1000 || $2 == 0' > "$RAW_DIR/login_users.txt" 2>/dev/null || true
grep -E '^(sudo|wheel|adm|docker):' /etc/group > "$RAW_DIR/privileged_groups.txt" 2>/dev/null || true
find /etc/sudoers /etc/sudoers.d -type f -exec ls -la {} + > "$RAW_DIR/sudoers_files.txt" 2>/dev/null || true

echo "[6/8] Auditing Container Runtimes (Docker / Podman)..."
if command -v docker >/dev/null 2>&1; then
    docker info --format 'SecurityOpts={{.SecurityOptions}} Driver={{.Driver}} LiveRestore={{.LiveRestoreEnabled}}' > "$RAW_DIR/docker_info.txt" 2>/dev/null || true
    docker ps -a --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' > "$RAW_DIR/docker_containers.txt" 2>/dev/null || true
fi
if command -v podman >/dev/null 2>&1; then
    podman ps -a --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' > "$RAW_DIR/podman_containers.txt" 2>/dev/null || true
fi

echo "[7/8] Checking Persistence Mechanisms (Timers, Crons, LD_PRELOAD)..."
if command -v systemctl >/dev/null 2>&1; then
    systemctl list-timers --all --no-pager > "$RAW_DIR/systemd_timers.txt" 2>/dev/null || true
fi
ls -la /etc/cron* /var/spool/cron/crontabs > "$RAW_DIR/crons.txt" 2>/dev/null || true
if [[ -f /etc/ld.so.preload ]]; then
    cat /etc/ld.so.preload > "$RAW_DIR/ld_preload.txt" 2>/dev/null || true
else
    echo "CLEAN: /etc/ld.so.preload does not exist" > "$RAW_DIR/ld_preload.txt"
fi

echo "[8/8] Scanning SUID/SGID Binaries and Key Permissions..."
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -exec ls -la {} + 2>/dev/null | sort -k1,1 > "$RAW_DIR/suid_sgid.txt" || true
ls -la /etc/ssh/ /root/.ssh/ > "$RAW_DIR/ssh_perms.txt" 2>/dev/null || true

echo "[*] Generating Structured JSON and Markdown Audit Reports..."

JSON_REPORT="$OUTPUT_DIR/vps_audit_${HOSTNAME}_$(date -u +%Y%m%d_%H%M%S).json"
MD_REPORT="$OUTPUT_DIR/vps_audit_${HOSTNAME}_$(date -u +%Y%m%d_%H%M%S).md"

python3 - "$RAW_DIR" "$JSON_REPORT" "$MD_REPORT" "$TIMESTAMP" "$HOSTNAME" << 'PYEOF'
import sys, os, json, pathlib

raw_dir = pathlib.Path(sys.argv[1])
json_path = pathlib.Path(sys.argv[2])
md_path = pathlib.Path(sys.argv[3])
timestamp = sys.argv[4]
hostname = sys.argv[5]

def read_file(name, default=""):
    p = raw_dir / name
    if p.exists():
        return p.read_text(encoding="utf-8", errors="replace").strip()
    return default

kernel = read_file("kernel_arch.txt")
os_rel = read_file("os_release.txt")
uptime = read_file("uptime.txt")
sysctl = read_file("sysctl_critical.txt")
sockets = read_file("listening_sockets.txt")
ufw = read_file("ufw_status.txt")
sshd = read_file("sshd_active.txt")
docker_info = read_file("docker_info.txt")
containers = read_file("docker_containers.txt")
ld_preload = read_file("ld_preload.txt")
suid_sgid = read_file("suid_sgid.txt")

# Findings parsing
findings = []

# Check SSH password authentication
if "passwordauthentication yes" in sshd.lower():
    findings.append({
        "id": "SEC-SSH-01",
        "severity": "HIGH",
        "cwe": "CWE-308",
        "cis": "CIS Linux 5.2.11",
        "title": "Password Authentication enabled in OpenSSH",
        "impact": "Allows brute-force and credential stuffing against SSH daemon.",
        "remediation": "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config.d/99-hardening.conf"
    })

# Check root login
if "permitrootlogin yes" in sshd.lower():
    findings.append({
        "id": "SEC-SSH-02",
        "severity": "HIGH",
        "cwe": "CWE-250",
        "cis": "CIS Linux 5.2.10",
        "title": "Direct Root Login with password allowed in OpenSSH",
        "impact": "Exposes root account to automated password dictionary attacks.",
        "remediation": "Set 'PermitRootLogin prohibit-password' in sshd config."
    })

# Check firewall
if not ufw and not read_file("iptables_v4.txt"):
    findings.append({
        "id": "SEC-NET-01",
        "severity": "CRITICAL",
        "cwe": "CWE-1188",
        "cis": "CIS Linux 3.5.1",
        "title": "No Host Firewall Active",
        "impact": "All listening sockets are directly reachable from external network.",
        "remediation": "Enable UFW or nftables with default deny incoming policy."
    })

# Check ASLR
if "kernel.randomize_va_space = 2" not in sysctl:
    findings.append({
        "id": "SEC-SYS-01",
        "severity": "MEDIUM",
        "cwe": "CWE-119",
        "cis": "CIS Linux 1.6.2",
        "title": "ASLR is not fully enabled",
        "impact": "Weakens memory corruption exploit mitigations.",
        "remediation": "sysctl -w kernel.randomize_va_space=2"
    })

report_data = {
    "version": "1.0.0",
    "target_host": hostname,
    "timestamp": timestamp,
    "operator_mode": "HYBRID_DEVSECOPS",
    "telemetry": {
        "kernel": kernel,
        "uptime": uptime,
        "sysctl_sample": sysctl.splitlines()[:10],
        "open_sockets_count": len(sockets.splitlines()),
        "docker_live_restore": "LiveRestore=true" in docker_info
    },
    "findings": findings,
    "findings_summary": {
        "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "high": sum(1 for f in findings if f["severity"] == "HIGH"),
        "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
        "low": sum(1 for f in findings if f["severity"] == "LOW"),
        "informative": sum(1 for f in findings if f["severity"] == "INFORMATIVE")
    }
}

json_path.write_text(json.dumps(report_data, indent=2), encoding="utf-8")

# Markdown Report Generation
md_lines = [
    f"# VPS CyberSec Audit Report — {hostname}",
    f"**Timestamp:** `{timestamp}` | **Auditor:** `VPS CyberSec Orchestrator`\n",
    "## 1. Executive Summary",
    f"- **Host Kernel:** `{kernel}`",
    f"- **Uptime:** `{uptime}`",
    f"- **Critical Findings:** {report_data['findings_summary']['critical']}",
    f"- **High Findings:** {report_data['findings_summary']['high']}",
    f"- **Medium Findings:** {report_data['findings_summary']['medium']}\n",
    "## 2. Identified Vulnerabilities & Hardening Opportunities\n",
    "| ID | Severity | Title | CIS / CWE | Suggested Remediation |",
    "|:---:|:---:|:---|:---:|:---|"
]

if findings:
    for f in findings:
        md_lines.append(f"| `{f['id']}` | **{f['severity']}** | {f['title']} | `{f.get('cis','-')}` / `{f.get('cwe','-')}` | {f['remediation']} |")
else:
    md_lines.append("| - | **CLEAN** | No critical vulnerabilities detected | - | Host aligns with baseline policies |")

md_lines.append("\n## 3. Next Steps")
md_lines.append("Execute idempotent hardening via `bin/vps_harden.sh --dry-run` to preview and apply automated corrections.")

md_path.write_text("\n".join(md_lines), encoding="utf-8")
print(f"[+] Audit JSON Report: {json_path}")
print(f"[+] Audit Markdown Report: {md_path}")
PYEOF

echo "========================================================================"
echo "✅ Audit completed successfully. Artifacts saved in $OUTPUT_DIR"
echo "========================================================================"
