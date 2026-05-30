#!/bin/bash
# ============================================================
# Linux Privilege Escalation Toolkit - Bash Enumeration Script
# Mode: Detection/Enumeration ONLY - No exploitation
# ============================================================

RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║  PrivEsc Bash Enumeration Script - Detection Only   ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

OUTFILE="bash_enum_output.txt"
echo "Scan Date: $(date)" > $OUTFILE
echo "======================================================" >> $OUTFILE

section() {
    echo -e "\n${BOLD}${YELLOW}[*] $1${NC}"
    echo "" >> $OUTFILE
    echo "=== $1 ===" >> $OUTFILE
}

log() {
    echo -e "    $1"
    echo "    $1" >> $OUTFILE
}

# ── System Info ──────────────────────────────────────────
section "System Information"
log "User       : $(whoami)"
log "Hostname   : $(hostname)"
log "Kernel     : $(uname -r)"
log "OS         : $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"')"
log "ID         : $(id)"
log "Home       : $HOME"
log "Shell      : $SHELL"

# ── SUID Binaries ────────────────────────────────────────
section "SUID Binaries"
GTFOBINS="awk bash busybox cp curl find gdb git less lua nmap node perl php python python3 ruby sed tar vim wget zip"
echo -e "  Scanning..." | tee -a $OUTFILE
while IFS= read -r binary; do
    name=$(basename "$binary")
    if echo "$GTFOBINS" | grep -qw "$name"; then
        echo -e "  ${RED}[HIGH]${NC} GTFOBins match: $binary" | tee -a $OUTFILE
    else
        echo -e "  ${GREEN}[LOW]${NC}  SUID binary: $binary" | tee -a $OUTFILE
    fi
done < <(find / -perm -4000 -type f 2>/dev/null)

# ── SGID Binaries ────────────────────────────────────────
section "SGID Binaries"
find / -perm -2000 -type f 2>/dev/null | while read -r f; do
    echo -e "  ${YELLOW}[MED]${NC} SGID: $f" | tee -a $OUTFILE
done

# ── World-Writable Files ─────────────────────────────────
section "World-Writable Files"
find / -writable -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" \
    -type f 2>/dev/null | head -30 | while read -r f; do
    echo -e "  ${YELLOW}[MED]${NC} Writable: $f" | tee -a $OUTFILE
done

# ── Critical File Permissions ────────────────────────────
section "Critical File Permissions"
for f in /etc/passwd /etc/shadow /etc/sudoers /etc/crontab; do
    if [ -f "$f" ]; then
        perms=$(stat -c "%a %n" "$f")
        echo -e "  ${CYAN}[INFO]${NC} $perms" | tee -a $OUTFILE
    fi
done

# ── Sudo Rules ───────────────────────────────────────────
section "Sudo Privileges"
sudo -l 2>/dev/null | while read -r line; do
    if echo "$line" | grep -q "NOPASSWD"; then
        echo -e "  ${RED}[HIGH]${NC} NOPASSWD: $line" | tee -a $OUTFILE
    else
        echo -e "  ${CYAN}[INFO]${NC} $line" | tee -a $OUTFILE
    fi
done

# ── Cron Jobs ────────────────────────────────────────────
section "Cron Jobs"
echo -e "  ${CYAN}/etc/crontab:${NC}" | tee -a $OUTFILE
cat /etc/crontab 2>/dev/null | grep -v "^#" | grep -v "^$" | tee -a $OUTFILE

for dir in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    if [ -d "$dir" ]; then
        echo -e "\n  ${CYAN}$dir:${NC}" | tee -a $OUTFILE
        ls -la "$dir" 2>/dev/null | tee -a $OUTFILE
    fi
done

echo -e "\n  ${CYAN}User crontab:${NC}" | tee -a $OUTFILE
crontab -l 2>/dev/null | grep -v "^#" | tee -a $OUTFILE

# ── Writable Cron Scripts ────────────────────────────────
section "Writable Cron Scripts"
grep -r "ExecStart\|command\|/" /etc/cron* 2>/dev/null | grep -v "^#" | awk -F'[= ]' '{print $NF}' | sort -u | while read -r script; do
    if [ -f "$script" ] && [ -w "$script" ]; then
        echo -e "  ${RED}[HIGH]${NC} WRITABLE cron script: $script" | tee -a $OUTFILE
    fi
done

# ── Kernel Info ──────────────────────────────────────────
section "Kernel Version"
KERNEL=$(uname -r)
echo -e "  Kernel: $KERNEL" | tee -a $OUTFILE
MAJOR=$(echo "$KERNEL" | cut -d. -f1)
MINOR=$(echo "$KERNEL" | cut -d. -f2)

if [ "$MAJOR" -lt 5 ]; then
    echo -e "  ${RED}[HIGH]${NC} Old kernel - check for Dirty COW (CVE-2016-5195), overlayfs LPE" | tee -a $OUTFILE
fi
if [ "$MAJOR" -eq 5 ] && [ "$MINOR" -le 8 ]; then
    echo -e "  ${RED}[HIGH]${NC} May be vulnerable to PwnKit (CVE-2021-4034)" | tee -a $OUTFILE
fi
if [ "$MAJOR" -eq 5 ] && [ "$MINOR" -le 16 ]; then
    echo -e "  ${RED}[HIGH]${NC} May be vulnerable to Dirty Pipe (CVE-2022-0847)" | tee -a $OUTFILE
fi

# ── Linux Capabilities ───────────────────────────────────
section "Linux Capabilities"
getcap -r / 2>/dev/null | while read -r cap; do
    echo -e "  ${YELLOW}[MED]${NC} Capability: $cap" | tee -a $OUTFILE
done

# ── Network Info ─────────────────────────────────────────
section "Network Interfaces & Open Ports"
ip addr 2>/dev/null | grep "inet " | tee -a $OUTFILE
echo "" >> $OUTFILE
ss -tlnp 2>/dev/null | head -20 | tee -a $OUTFILE

# ── Running Processes ────────────────────────────────────
section "Processes Running as Root"
ps aux 2>/dev/null | grep "^root" | grep -v "grep" | head -15 | tee -a $OUTFILE

# ── PATH Hijacking ───────────────────────────────────────
section "PATH Variable"
echo -e "  PATH: $PATH" | tee -a $OUTFILE
if echo "$PATH" | grep -q "\."; then
    echo -e "  ${RED}[HIGH]${NC} PATH contains '.' - PATH hijacking possible!" | tee -a $OUTFILE
fi
if echo "$PATH" | grep -q "^:"; then
    echo -e "  ${RED}[HIGH]${NC} PATH starts with ':' - relative path hijacking possible!" | tee -a $OUTFILE
fi

echo -e "\n${GREEN}${BOLD}[+] Enumeration complete! Output saved to: $OUTFILE${NC}"
