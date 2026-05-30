#!/usr/bin/env python3
"""
====================================================
Linux Privilege Escalation Automation Toolkit
====================================================
Author  : Security Audit Toolkit
Purpose : Automated scanning for privilege escalation
          vectors - Detection ONLY (No exploitation)
====================================================
"""

import os
import subprocess
import sys
import json
import re
from datetime import datetime

# ─── Color Codes ────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ─── GTFOBins High-Risk Binaries ────────────────
GTFOBINS = [
    "awk", "bash", "busybox", "cp", "curl", "cut", "dash", "dd", "diff",
    "dmesg", "ed", "env", "expand", "expect", "find", "flock", "fmt",
    "fold", "gdb", "git", "grep", "head", "ionice", "jjs", "jq",
    "less", "lua", "make", "more", "mv", "nawk", "nice", "nl", "nmap",
    "node", "od", "perl", "php", "python", "python2", "python3", "ruby",
    "run-parts", "sed", "shuf", "socat", "sort", "sqlite3", "ssh",
    "stdbuf", "strace", "tail", "tar", "taskset", "tee", "telnet",
    "tclsh", "timeout", "tmux", "ul", "unexpand", "uniq", "unshare",
    "vi", "vim", "watch", "wget", "xargs", "xxd", "zip", "zsh"
]

findings = {
    "system_info": {},
    "suid_sgid": [],
    "weak_permissions": [],
    "services": [],
    "cron_jobs": [],
    "kernel": {},
    "sudo_rules": [],
    "capabilities": []
}

# ─── Helpers ────────────────────────────────────

def run_cmd(cmd, shell=True):
    try:
        result = subprocess.run(
            cmd, shell=shell, capture_output=True,
            text=True, timeout=15
        )
        return result.stdout.strip()
    except Exception:
        return ""

def banner():
    print(f"""
{BOLD}{CYAN}
╔══════════════════════════════════════════════════════════════╗
║      Linux Privilege Escalation Automation Toolkit          ║
║      Mode: DETECTION ONLY  |  No Exploitation Performed     ║
╚══════════════════════════════════════════════════════════════╝
{RESET}""")

def section(title):
    print(f"\n{BOLD}{YELLOW}{'═'*60}{RESET}")
    print(f"{BOLD}{CYAN}  [*] {title}{RESET}")
    print(f"{BOLD}{YELLOW}{'═'*60}{RESET}")

def finding(severity, msg):
    icons = {"HIGH": f"{RED}[HIGH]{RESET}", "MEDIUM": f"{YELLOW}[MED]{RESET}", "LOW": f"{GREEN}[LOW]{RESET}"}
    icon = icons.get(severity, "[INFO]")
    print(f"  {icon} {msg}")

# ════════════════════════════════════════════════
# STEP 1: System Information
# ════════════════════════════════════════════════

def collect_system_info():
    section("STEP 1: System Information Collection")

    user       = run_cmd("whoami")
    hostname   = run_cmd("hostname")
    kernel     = run_cmd("uname -r")
    os_info    = run_cmd("cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"'")
    groups     = run_cmd("id")
    arch       = run_cmd("uname -m")
    uptime_val = run_cmd("uptime -p")

    info = {
        "user": user,
        "hostname": hostname,
        "kernel": kernel,
        "os": os_info,
        "groups": groups,
        "arch": arch,
        "uptime": uptime_val
    }
    findings["system_info"] = info

    print(f"  User      : {BOLD}{user}{RESET}")
    print(f"  Hostname  : {hostname}")
    print(f"  OS        : {os_info}")
    print(f"  Kernel    : {kernel}")
    print(f"  Arch      : {arch}")
    print(f"  ID / Groups: {groups}")

    if user == "root":
        print(f"\n  {GREEN}[+] Already running as root!{RESET}")
    else:
        print(f"\n  {YELLOW}[~] Running as non-root user: {user}{RESET}")

    return info

# ════════════════════════════════════════════════
# STEP 2A: SUID / SGID Binary Discovery
# ════════════════════════════════════════════════

def scan_suid_sgid():
    section("STEP 2A: SUID/SGID Binary Discovery")

    print("  Scanning filesystem for SUID/SGID binaries (this may take a moment)...")
    suid_raw = run_cmd("find / -perm -4000 -type f 2>/dev/null")
    sgid_raw = run_cmd("find / -perm -2000 -type f 2>/dev/null")

    suid_list = [x for x in suid_raw.splitlines() if x]
    sgid_list = [x for x in sgid_raw.splitlines() if x]

    print(f"\n  Found {len(suid_list)} SUID binaries, {len(sgid_list)} SGID binaries")

    # Check against GTFOBins
    risky = []
    for path in suid_list + sgid_list:
        binary_name = os.path.basename(path).lower()
        if binary_name in GTFOBINS:
            risky.append({"path": path, "name": binary_name, "type": "SUID" if path in suid_list else "SGID"})
            finding("HIGH", f"GTFOBins match: {path}  →  exploit possible via {binary_name}")
            findings["suid_sgid"].append({
                "severity": "HIGH",
                "path": path,
                "binary": binary_name,
                "note": f"Listed in GTFOBins - can be abused for privilege escalation"
            })

    # Non-risky SUID
    for path in suid_list:
        name = os.path.basename(path).lower()
        if name not in GTFOBINS:
            findings["suid_sgid"].append({
                "severity": "LOW",
                "path": path,
                "binary": name,
                "note": "SUID binary - review manually"
            })
            finding("LOW", f"SUID (non-GTFOBins): {path}")

    if not risky:
        print(f"  {GREEN}[+] No GTFOBins-matched SUID/SGID binaries found.{RESET}")

    return risky

# ════════════════════════════════════════════════
# STEP 2B: Weak File & Directory Permissions
# ════════════════════════════════════════════════

def scan_weak_permissions():
    section("STEP 2B: Weak File & Directory Permissions")

    # World-writable files (non-symlinks)
    print("  Scanning for world-writable files...")
    ww_raw = run_cmd("find / -writable -not -path '/proc/*' -not -path '/sys/*' -not -path '/dev/*' -type f 2>/dev/null | head -50")
    ww_files = [x for x in ww_raw.splitlines() if x]

    for f in ww_files:
        finding("MEDIUM", f"World-writable file: {f}")
        findings["weak_permissions"].append({
            "severity": "MEDIUM",
            "path": f,
            "issue": "World-writable file"
        })

    # Critical file permissions
    critical_files = {
        "/etc/passwd":  "644",
        "/etc/shadow":  "640",
        "/etc/sudoers": "440",
        "/etc/crontab": "644",
        "/etc/hosts":   "644",
    }

    print("\n  Checking critical file permissions...")
    for filepath, expected in critical_files.items():
        if os.path.exists(filepath):
            try:
                mode = oct(os.stat(filepath).st_mode)[-3:]
                # Check if world-writable or readable when shouldn't be
                if filepath == "/etc/shadow" and mode[-1] in ["6","7","2","3"]:
                    finding("HIGH", f"{filepath} is world-readable/writable! (mode: {mode})")
                    findings["weak_permissions"].append({
                        "severity": "HIGH",
                        "path": filepath,
                        "issue": f"World-readable shadow file (mode {mode})"
                    })
                elif filepath == "/etc/passwd" and "7" in mode or "6" in mode[2]:
                    finding("HIGH", f"{filepath} is world-writable! (mode: {mode})")
                    findings["weak_permissions"].append({
                        "severity": "HIGH",
                        "path": filepath,
                        "issue": f"World-writable passwd file (mode {mode})"
                    })
                else:
                    finding("LOW", f"{filepath} permissions OK (mode: {mode})")
            except Exception:
                pass

    # World-writable directories
    print("\n  Scanning for world-writable directories...")
    ww_dirs = run_cmd("find / -writable -not -path '/proc/*' -not -path '/sys/*' -not -path '/dev/*' -not -path '/run/*' -type d 2>/dev/null | head -20")
    for d in ww_dirs.splitlines():
        if d and "/tmp" not in d and "/var/tmp" not in d:
            finding("MEDIUM", f"World-writable directory: {d}")
            findings["weak_permissions"].append({
                "severity": "MEDIUM",
                "path": d,
                "issue": "World-writable directory"
            })

# ════════════════════════════════════════════════
# STEP 2C: Misconfigured Services
# ════════════════════════════════════════════════

def scan_services():
    section("STEP 2C: Misconfigured Systemd Services")

    # Sudo rules
    print("  Checking sudo privileges...")
    sudo_out = run_cmd("sudo -l 2>/dev/null")
    if sudo_out:
        lines = sudo_out.splitlines()
        for line in lines:
            line = line.strip()
            if "NOPASSWD" in line:
                finding("HIGH", f"NOPASSWD sudo rule: {line}")
                findings["sudo_rules"].append({
                    "severity": "HIGH",
                    "rule": line,
                    "note": "NOPASSWD rule - can execute as root without password"
                })
            elif "(ALL" in line or "(root" in line:
                finding("MEDIUM", f"Broad sudo rule: {line}")
                findings["sudo_rules"].append({
                    "severity": "MEDIUM",
                    "rule": line,
                    "note": "Broad privilege rule"
                })
    else:
        print(f"  {GREEN}[+] No sudo privileges found for current user.{RESET}")

    # Systemd services running as root with user-writable ExecStart
    print("\n  Scanning systemd service files...")
    service_dirs = ["/etc/systemd/system/", "/lib/systemd/system/"]
    for sdir in service_dirs:
        if not os.path.isdir(sdir):
            continue
        for fname in os.listdir(sdir):
            if not fname.endswith(".service"):
                continue
            fpath = os.path.join(sdir, fname)
            try:
                with open(fpath) as f:
                    content = f.read()
                # Check for user=root and an ExecStart path that is writable
                if "User=root" in content or ("User=" not in content and "ExecStart=" in content):
                    for line in content.splitlines():
                        if line.startswith("ExecStart="):
                            bin_path = line.split("=", 1)[1].split()[0].strip()
                            if os.path.exists(bin_path) and os.access(bin_path, os.W_OK):
                                finding("HIGH", f"Service {fname}: ExecStart={bin_path} is writable!")
                                findings["services"].append({
                                    "severity": "HIGH",
                                    "service": fname,
                                    "path": bin_path,
                                    "note": "Writable ExecStart binary in root-level service"
                                })
                # Insecure PATH in service
                if "PATH=." in content or "PATH=:" in content:
                    finding("MEDIUM", f"Insecure PATH in service: {fname}")
                    findings["services"].append({
                        "severity": "MEDIUM",
                        "service": fname,
                        "path": fpath,
                        "note": "Insecure PATH variable includes current directory"
                    })
            except Exception:
                pass

    # Linux capabilities
    print("\n  Scanning for elevated Linux capabilities...")
    caps_out = run_cmd("getcap -r / 2>/dev/null")
    if caps_out:
        for line in caps_out.splitlines():
            if line:
                finding("MEDIUM", f"Capability set: {line}")
                findings["capabilities"].append({
                    "severity": "MEDIUM",
                    "entry": line,
                    "note": "Binary has elevated capabilities"
                })
    else:
        print(f"  {GREEN}[+] No special capabilities found.{RESET}")

# ════════════════════════════════════════════════
# STEP 2D: Cron Job Vulnerabilities
# ════════════════════════════════════════════════

def scan_cron():
    section("STEP 2D: Cron Job Vulnerabilities")

    cron_sources = [
        "/etc/crontab",
        "/etc/cron.d/",
        "/var/spool/cron/crontabs/",
        "/etc/cron.hourly/",
        "/etc/cron.daily/",
        "/etc/cron.weekly/",
        "/etc/cron.monthly/"
    ]

    def check_cron_entry(schedule, cmd, source):
        # Extract the script/binary path
        tokens = cmd.split()
        for tok in tokens:
            if tok.startswith("/") and os.path.exists(tok):
                if os.access(tok, os.W_OK):
                    finding("HIGH", f"Writable cron script: {tok}  (from {source})")
                    findings["cron_jobs"].append({
                        "severity": "HIGH",
                        "path": tok,
                        "schedule": schedule,
                        "source": source,
                        "note": "Writable script executed by cron - replace for privilege escalation"
                    })
                    return
                else:
                    finding("LOW", f"Cron script found: {tok}  (schedule: {schedule})")
                    findings["cron_jobs"].append({
                        "severity": "LOW",
                        "path": tok,
                        "schedule": schedule,
                        "source": source,
                        "note": "Cron script - check directory write permissions"
                    })
                break

    def parse_crontab_file(filepath):
        try:
            with open(filepath) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = line.split()
                        if len(parts) >= 6:
                            schedule = " ".join(parts[:5])
                            cmd = " ".join(parts[5:])
                            check_cron_entry(schedule, cmd, filepath)
        except Exception:
            pass

    def parse_cron_dir(dirpath):
        if not os.path.isdir(dirpath):
            return
        for fname in os.listdir(dirpath):
            fpath = os.path.join(dirpath, fname)
            if os.path.isfile(fpath):
                parse_crontab_file(fpath)
            elif os.path.isdir(fpath):
                for script in os.listdir(fpath):
                    spath = os.path.join(fpath, script)
                    check_cron_entry(fname, spath, fpath)

    for src in cron_sources:
        if os.path.isfile(src):
            parse_crontab_file(src)
        elif os.path.isdir(src):
            parse_cron_dir(src)

    # User crontab
    user_cron = run_cmd("crontab -l 2>/dev/null")
    if user_cron and "no crontab" not in user_cron.lower():
        for line in user_cron.splitlines():
            if line and not line.startswith("#"):
                finding("LOW", f"User cron entry: {line}")

    if not findings["cron_jobs"]:
        print(f"  {GREEN}[+] No vulnerable cron jobs detected.{RESET}")

# ════════════════════════════════════════════════
# STEP 2E: Kernel Exploit Detection
# ════════════════════════════════════════════════

def scan_kernel():
    section("STEP 2E: Kernel Exploit Detection")

    kernel_ver = run_cmd("uname -r")
    os_release = run_cmd("cat /etc/os-release 2>/dev/null")
    lsb_info   = run_cmd("lsb_release -a 2>/dev/null")

    findings["kernel"]["version"] = kernel_ver
    print(f"  Kernel version: {BOLD}{kernel_ver}{RESET}")

    # Extract major.minor version
    match = re.match(r"(\d+)\.(\d+)", kernel_ver)
    if match:
        major, minor = int(match.group(1)), int(match.group(2))

        # Known vulnerable kernel version ranges (CVE references)
        known_vulns = [
            {"range": (major == 5 and minor <= 8),  "cve": "CVE-2021-4034",  "name": "PwnKit (Polkit)",           "severity": "HIGH"},
            {"range": (major == 5 and minor <= 11), "cve": "CVE-2021-3156",  "name": "Sudo Baron Samedit",        "severity": "HIGH"},
            {"range": (major == 4 and minor <= 4),  "cve": "CVE-2016-5195",  "name": "Dirty COW",                 "severity": "HIGH"},
            {"range": (major == 3 and minor <= 19), "cve": "CVE-2015-1328",  "name": "overlayfs LPE",             "severity": "HIGH"},
            {"range": (major == 5 and minor <= 16), "cve": "CVE-2022-0847",  "name": "Dirty Pipe",                "severity": "HIGH"},
            {"range": (major == 4 and minor <= 14), "cve": "CVE-2018-18955", "name": "User NS Escape",            "severity": "MEDIUM"},
            {"range": (major <= 4),                 "cve": "CVE-2017-16995", "name": "eBPF priv escalation",      "severity": "MEDIUM"},
        ]

        for vuln in known_vulns:
            if vuln["range"]:
                finding(vuln["severity"],
                        f"Possible {vuln['cve']} ({vuln['name']}) - kernel {kernel_ver}")
                findings["kernel"].setdefault("cves", []).append({
                    "cve": vuln["cve"],
                    "name": vuln["name"],
                    "severity": vuln["severity"]
                })

        if major < 5 or (major == 5 and minor < 15):
            finding("MEDIUM", f"Kernel {kernel_ver} may be outdated. Consider upgrading to 6.x LTS.")
            findings["kernel"]["outdated"] = True
        else:
            print(f"  {GREEN}[+] Kernel version appears relatively modern.{RESET}")

    # Check if kernel is end-of-life
    eol_kernels = ["3.", "4.4.", "4.9.", "4.14.", "4.19.", "5.4.", "5.10.", "5.15."]
    for eol in eol_kernels:
        if kernel_ver.startswith(eol):
            finding("MEDIUM", f"Kernel series {eol}x may be approaching/past EOL.")
            break

# ════════════════════════════════════════════════
# STEP 3 & 4: Analyze + Generate Report
# ════════════════════════════════════════════════

def count_by_severity():
    total = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    all_items = (
        findings["suid_sgid"] +
        findings["weak_permissions"] +
        findings["services"] +
        findings["cron_jobs"] +
        findings["sudo_rules"] +
        findings["capabilities"]
    )
    for item in all_items:
        s = item.get("severity", "LOW")
        total[s] = total.get(s, 0) + 1
    # Kernel CVEs
    for cve in findings["kernel"].get("cves", []):
        total[cve["severity"]] = total.get(cve["severity"], 0) + 1
    return total, all_items

def generate_text_report():
    section("STEP 4: Final Security Report")

    counts, all_items = count_by_severity()
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report = []
    report.append("=" * 70)
    report.append("  LINUX PRIVILEGE ESCALATION AUDIT REPORT")
    report.append(f"  Generated : {ts}")
    report.append(f"  Host      : {findings['system_info'].get('hostname','unknown')}")
    report.append(f"  User      : {findings['system_info'].get('user','unknown')}")
    report.append(f"  OS        : {findings['system_info'].get('os','unknown')}")
    report.append(f"  Kernel    : {findings['system_info'].get('kernel','unknown')}")
    report.append("=" * 70)
    report.append(f"\n  SUMMARY: {counts['HIGH']} HIGH | {counts['MEDIUM']} MEDIUM | {counts['LOW']} LOW findings\n")

    categories = [
        ("SUID/SGID Binaries",     findings["suid_sgid"]),
        ("Weak Permissions",        findings["weak_permissions"]),
        ("Misconfigured Services",  findings["services"]),
        ("Cron Job Vulnerabilities",findings["cron_jobs"]),
        ("Sudo Misconfigurations",  findings["sudo_rules"]),
        ("Linux Capabilities",      findings["capabilities"]),
    ]

    mitigation_map = {
        "SUID/SGID Binaries":      "Remove SUID bit with: chmod u-s <binary>. Only set SUID on essential binaries.",
        "Weak Permissions":         "Fix with chmod. /etc/shadow should be 640, /etc/passwd 644.",
        "Misconfigured Services":   "Ensure service ExecStart binaries are owned by root and not world-writable.",
        "Cron Job Vulnerabilities": "Restrict cron scripts to root ownership (chmod 700, chown root).",
        "Sudo Misconfigurations":   "Remove NOPASSWD rules. Use specific commands, never ALL.",
        "Linux Capabilities":       "Audit with getcap -r /. Remove unnecessary caps with setcap -r <binary>.",
    }

    for cat_name, items in categories:
        if items:
            report.append(f"\n{'─'*60}")
            report.append(f"  [{cat_name.upper()}]")
            report.append(f"{'─'*60}")
            for item in items:
                sev  = item.get("severity", "?")
                path = item.get("path") or item.get("rule") or item.get("entry") or ""
                note = item.get("note", "")
                report.append(f"  [{sev:6}] {path}")
                report.append(f"           {note}")
            report.append(f"\n  Mitigation: {mitigation_map.get(cat_name,'Review and harden.')}")

    # Kernel CVEs
    if findings["kernel"].get("cves"):
        report.append(f"\n{'─'*60}")
        report.append("  [KERNEL VULNERABILITIES]")
        report.append(f"{'─'*60}")
        for cve in findings["kernel"]["cves"]:
            report.append(f"  [{cve['severity']:6}] {cve['cve']} - {cve['name']}")
        report.append("\n  Mitigation: Apply kernel updates: sudo apt update && sudo apt upgrade -y")
        report.append("              For LTS: upgrade to 6.x series. Monitor https://ubuntu.com/security/cves")

    report.append(f"\n{'='*70}")
    report.append("  END OF REPORT")
    report.append(f"{'='*70}\n")

    report_text = "\n".join(report)
    print(report_text)

    # Save to file
    report_path = "audit_report.txt"
    with open(report_path, "w") as f:
        f.write(report_text)

    # Save JSON findings
    json_path = "audit_findings.json"
    with open(json_path, "w") as f:
        json.dump(findings, f, indent=2)

    print(f"  {GREEN}[+] Report saved to: {report_path}{RESET}")
    print(f"  {GREEN}[+] JSON data saved to: {json_path}{RESET}")
    return report_text

# ════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════

def main():
    banner()
    print(f"  Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  {YELLOW}WARNING: This tool performs READ-ONLY detection. No exploitation occurs.{RESET}\n")

    collect_system_info()
    scan_suid_sgid()
    scan_weak_permissions()
    scan_services()
    scan_cron()
    scan_kernel()
    generate_text_report()

if __name__ == "__main__":
    main()
