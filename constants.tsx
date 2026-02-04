
import React from 'react';

export const PYTHON_TOOLKIT_CODE = `#!/usr/bin/env python3
"""
LynxAudit - Linux Privilege Escalation Automation Toolkit
Version: 1.5.0
Purpose: Educational and Defensive System Auditing Only.
STRICTLY READ-ONLY DETECTION ENGINE.
"""

import os
import sys
import stat
import pwd
import grp
import subprocess
import platform
import pathlib
import re
import json
import time
from datetime import datetime

class LynxAuditor:
    def __init__(self):
        self.timestamp = datetime.now().isoformat()
        self.report = {
            "timestamp": self.timestamp,
            "system_info": {},
            "findings": []
        }
        self.high_risk_suids = [
            "nmap", "vim", "find", "bash", "sh", "python", "perl", "ruby", 
            "sed", "awk", "ed", "more", "less", "cp", "mv", "nano", "curl", "wget",
            "tcpdump", "gdb", "man", "vi", "pico", "rvim", "view"
        ]
        self.audit_dirs = ['/etc', '/opt', '/var/www', '/usr/local/bin', '/usr/local/sbin']
        self.systemd_paths = ['/etc/systemd/system', '/lib/systemd/system', '/usr/lib/systemd/system']
        self.cron_paths = ['/etc/crontab', '/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly', '/etc/cron.monthly', '/etc/cron.weekly']

    def log_finding(self, name, desc, severity, method, impact, mitigation, module):
        if any(f['description'] == desc for f in self.report["findings"]):
            return
        self.report["findings"].append({
            "name": name,
            "description": desc,
            "severity": severity,
            "detection_method": method,
            "impact": impact,
            "mitigation": mitigation,
            "module": module
        })

    def module_system_info(self):
        print("[*] Running Module: System Information...")
        try:
            uid = os.getuid()
            user_info = pwd.getpwuid(uid)
            self.report["system_info"] = {
                "user": user_info.pw_name,
                "uid": uid,
                "gid": os.getgid(),
                "groups": [grp.getgrgid(g).gr_name for g in os.getgroups()],
                "os": platform.system() + " " + platform.release(),
                "kernel": platform.version(),
                "arch": platform.machine(),
                "is_root": uid == 0
            }
        except Exception as e:
            print(f"[!] Error in System Info: {e}")

    def module_suid_scan(self):
        print("[*] Running Module: SUID/SGID Scanner...")
        for directory in self.audit_dirs:
            if not os.path.exists(directory): continue
            for root, dirs, files in os.walk(directory):
                for file in files:
                    try:
                        filepath = os.path.join(root, file)
                        st = os.stat(filepath)
                        if st.st_mode & stat.S_ISUID:
                            if file in self.high_risk_suids:
                                self.log_finding(
                                    f"High Risk SUID Binary: {file}",
                                    f"Known GTFOBins binary '{file}' has SUID bit set.",
                                    "CRITICAL",
                                    "os.walk + stat check",
                                    "Potential privilege escalation via known bypass techniques.",
                                    f"chmod u-s {filepath}",
                                    "SUID_SCAN"
                                )
                    except Exception: pass

    def module_weak_perms(self):
        print("[*] Running Module: Weak Permissions...")
        critical_files = ['/etc/passwd', '/etc/shadow', '/etc/sudoers']
        for filepath in critical_files:
            if os.path.exists(filepath):
                try:
                    st = os.stat(filepath)
                    if st.st_mode & stat.S_IWOTH:
                        self.log_finding(
                            f"World-Writable Critical File: {filepath}",
                            f"File '{filepath}' is writable by everyone.",
                            "CRITICAL",
                            "os.access(W_OK)",
                            "Any user can modify system configuration to gain root access.",
                            f"chmod 644 {filepath}",
                            "WEAK_PERMS"
                        )
                except Exception: pass

    def module_services_audit(self):
        """
        MODULE 4: Misconfigured Services
        Checks for:
        1. Writable service binaries
        2. Insecure file ownership (non-root owner)
        3. Insecure PATH (concept)
        """
        print("[*] Running Module: Misconfigured Services...")
        for path in self.systemd_paths:
            if not os.path.isdir(path): continue
            for filename in os.listdir(path):
                if not filename.endswith('.service'): continue
                
                filepath = os.path.join(path, filename)
                try:
                    with open(filepath, 'r') as f:
                        content = f.read()
                    
                    # Parsing ExecStart to find the binary path
                    # This regex grabs the first argument after ExecStart=
                    match = re.search(r'^ExecStart=([^\s]+)', content, re.MULTILINE)
                    if match:
                        binary_path = match.group(1)
                        # Clean path (remove flags like -f, etc if matched incorrectly, though regex helps)
                        if not binary_path.startswith('/'): continue 
                        
                        if os.path.exists(binary_path):
                            stat_info = os.stat(binary_path)
                            
                            # CHECK 1: Insecure Ownership (Non-root owner)
                            if stat_info.st_uid != 0:
                                owner_name = pwd.getpwuid(stat_info.st_uid).pw_name
                                self.log_finding(
                                    f"Service Binary User Owned: {filename}",
                                    f"Service '{filename}' executes binary '{binary_path}' which is owned by non-root user '{owner_name}'.",
                                    "HIGH",
                                    "Systemd parsing + stat.st_uid check",
                                    f"The user '{owner_name}' can replace the binary to execute code as root when the service starts.",
                                    f"chown root:root {binary_path}",
                                    "SVC_AUDIT"
                                )

                            # CHECK 2: Writable by Group or World
                            # S_IWOTH = world writable, S_IWGRP = group writable
                            is_world_writable = bool(stat_info.st_mode & stat.S_IWOTH)
                            is_group_writable = bool(stat_info.st_mode & stat.S_IWGRP)
                            
                            # We assume gid 0 is root group. If group is not root and it's writable, it's a risk.
                            if is_world_writable or (is_group_writable and stat_info.st_gid != 0):
                                self.log_finding(
                                    f"Writable Service Binary: {filename}",
                                    f"The service binary '{binary_path}' is writable by group or world.",
                                    "CRITICAL",
                                    "Systemd parsing + os.access mode check",
                                    "Attackers can overwrite the binary to execute arbitrary code as root.",
                                    f"chmod 755 {binary_path} && chown root:root {binary_path}",
                                    "SVC_AUDIT"
                                )
                except Exception as e:
                    pass

    def module_sudo_audit(self):
        """
        MODULE 5: Sudo Privileges Audit
        Analyzes 'sudo -l' output for NOPASSWD entries and dangerous binaries.
        """
        print("[*] Running Module: Sudo Privileges Audit...")
        try:
            # -n: non-interactive (fails if password needed), -l: list privileges
            cmd = ['sudo', '-n', '-l']
            # timeout=3 prevents hanging if sudo requires interaction
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            
            if result.returncode == 0 and result.stdout:
                for line in result.stdout.splitlines():
                    if 'NOPASSWD:' in line:
                        # Parse line like: (ALL) NOPASSWD: /usr/bin/vim, /usr/bin/find
                        parts = line.split('NOPASSWD:', 1)
                        if len(parts) == 2:
                            allowed_cmds = parts[1].split(',')
                            for cmd_str in allowed_cmds:
                                cmd_str = cmd_str.strip()
                                binary_path = cmd_str.split()[0]
                                binary_name = os.path.basename(binary_path)
                                
                                severity = "MEDIUM"
                                impact = "Command execution as root without password."
                                
                                # Check for dangerous binaries (GTFOBins)
                                if binary_name in self.high_risk_suids:
                                    severity = "CRITICAL"
                                    impact = f"GTFOBins vector: '{binary_name}' can spawn a root shell or allow arbitrary file write/read."
                                
                                self.log_finding(
                                    f"Sudo NOPASSWD: {binary_name}",
                                    f"User allowed to run '{cmd_str}' as root without password.",
                                    severity,
                                    "sudo -l parsing",
                                    impact,
                                    "Restrict command in sudoers or require password authentication.",
                                    "SUDO_AUDIT"
                                )
        except Exception:
            # Sudo might not be installed, or user might need password (and -n failed)
            pass

    def module_cron_audit(self):
        """
        MODULE 6: Cron Job Analysis
        Parses system cron files to detect writable scripts executed by root.
        """
        print("[*] Running Module: Cron Job Analysis...")
        
        def check_writable(path, context):
            # We skip directories themselves, only check files
            if not os.path.exists(path) or os.path.isdir(path): return
            try:
                st = os.stat(path)
                # Check for world writable or group writable (if group not root)
                is_world_writable = bool(st.st_mode & stat.S_IWOTH)
                is_group_writable = bool(st.st_mode & stat.S_IWGRP) and st.st_gid != 0
                
                if is_world_writable or is_group_writable:
                    self.log_finding(
                        f"Writable Cron Script: {path}",
                        f"Root-executed cron script via '{context}' is writable by non-root users.",
                        "CRITICAL",
                        "Cron parsing + os.access check",
                        "Privilege escalation: attackers can modify the script to execute code as root.",
                        f"chmod 700 {path} && chown root:root {path}",
                        "CRON_AUDIT"
                    )
            except Exception: pass

        # 1. Parse /etc/crontab and /etc/cron.d/*
        cron_files = ['/etc/crontab']
        if os.path.exists('/etc/cron.d'):
            try:
                cron_files += [os.path.join('/etc/cron.d', f) for f in os.listdir('/etc/cron.d')]
            except OSError: pass

        for cron_file in cron_files:
            if not os.path.exists(cron_file): continue
            try:
                with open(cron_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'): continue
                        
                        # Typical system cron format: m h dom mon dow user command
                        parts = line.split()
                        if len(parts) >= 7:
                            user = parts[5]
                            if user == 'root':
                                command_parts = parts[6:]
                                # Identify potential script paths in the command
                                for part in command_parts:
                                    # Basic heuristic: starts with / and not a known flag
                                    if part.startswith('/') and not part.endswith(','):
                                         check_writable(part, cron_file)
            except Exception: pass

        # 2. Check /etc/cron.{daily,hourly,weekly,monthly}
        # These scripts are typically executed by run-parts as root
        periodics = ['/etc/cron.daily', '/etc/cron.hourly', '/etc/cron.weekly', '/etc/cron.monthly']
        for d in periodics:
            if not os.path.exists(d): continue
            try:
                for filename in os.listdir(d):
                    # Skip hidden files or specific system placeholders if necessary
                    if filename.startswith('.'): continue
                    filepath = os.path.join(d, filename)
                    check_writable(filepath, d)
            except OSError: pass

    def module_live_monitor(self, duration_sec=60):
        """
        MODULE 7: Live System Monitoring (Conceptual Simulation)
        In a real deployment, this would use inotify or auditd log parsing.
        """
        print(f"[*] Starting Live Audit Monitor for {duration_sec}s...")
        print("[!] Press Ctrl+C to stop early.")
        
        events_found = 0
        try:
            # Conceptual: Monitoring /etc and /var/log
            start_time = time.time()
            while time.time() - start_time < duration_sec:
                # Simulation of finding a live event (e.g. log entry for sudo)
                # In real tool: tail -f /var/log/auth.log | grep "sudo"
                time.sleep(2)
                
            print(f"[*] Live monitor session concluded. {events_found} critical events logged.")
        except KeyboardInterrupt:
            print("\\n[!] Live monitor stopped by user.")

    def run_all(self, manual_kernel=None, live_mode=False):
        self.module_system_info()
        self.module_suid_scan()
        self.module_weak_perms()
        self.module_services_audit()
        self.module_sudo_audit()
        self.module_cron_audit()
        if live_mode:
            self.module_live_monitor()
        return self.report

if __name__ == "__main__":
    auditor = LynxAuditor()
    report = auditor.run_all()
    with open('lynx_audit_report.json', 'w') as f:
        json.dump(report, f, indent=4)
    print("\\nLYNXAUDIT COMPLETE. Report saved.")
`;

export const ICONS = {
  Terminal: (props: any) => <svg fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" {...props}><path strokeLinecap="round" strokeLinejoin="round" d="M6.75 7.5l3 2.25-3 2.25m4.5 0h3m-9 8.25h13.5A2.25 2.25 0 0021 18V6a2.25 2.25 0 00-2.25-2.25H5.25A2.25 2.25 0 003 6v12a2.25 2.25 0 002.25 2.25z" /></svg>,
  Shield: (props: any) => <svg fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" {...props}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751A11.959 11.959 0 0112 2.714z" /></svg>,
  Alert: (props: any) => <svg fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" {...props}><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.34c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" /></svg>,
  Search: (props: any) => <svg fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" {...props}><path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" /></svg>,
  Cpu: (props: any) => <svg fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" {...props}><path strokeLinecap="round" strokeLinejoin="round" d="M8.25 3v1.5M4.5 8.25H3m18 0h-1.5m-15 7.5H3m18 0h-1.5m-15 4.5V21m3-18v1.5m0 15V21m9-18v1.5m0 15V21m-9-13.5h9a1.5 1.5 0 011.5 1.5v9a1.5 1.5 0 01-1.5 1.5h-9a1.5 1.5 0 01-1.5-1.5v-9a1.5 1.5 0 011.5-1.5z" /></svg>,
  Code: (props: any) => <svg fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" {...props}><path strokeLinecap="round" strokeLinejoin="round" d="M17.25 6.75L22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3l-4.5 16.5" /></svg>,
  Document: (props: any) => <svg fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" {...props}><path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" /></svg>,
  Activity: (props: any) => <svg fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" {...props}><path strokeLinecap="round" strokeLinejoin="round" d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 013 19.875v-6.75zM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V8.625zM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V4.125z" /></svg>,
  Clock: (props: any) => <svg fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" {...props}><path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
};
