# Linux-Privilege-Escalation-Automation-Toolkit
Automated Linux Privilege Escalation Scanner - Cybersecurity Project


Automated scanner for detecting Linux privilege escalation vulnerabilities.
Detection ONLY — No exploitation performed.

## Files
- privesc_scanner.py — Main Python scanner
- enum.sh — Bash enumeration script
- audit_report.txt — Sample generated report
- Linux_PrivEsc_Toolkit_Documentation.docx — Full documentation

## How to Run
```bash
sudo python3 privesc_scanner.py
bash enum.sh
```

## Modules
1. SUID/SGID Binary Discovery
2. Weak File & Directory Permissions
3. Misconfigured Services & Sudo Rules
4. Cron Job Vulnerabilities
5. Kernel CVE Detection
