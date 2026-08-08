#!/usr/bin/env python3
"""
Ubuntu Security Hardening Engine
Automated Security Hardening & Remediation Framework for Ubuntu Linux.
"""

import sys
import os
import shutil
import json
import argparse
import subprocess
import datetime
from pathlib import Path

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class SecurityHardener:
    def __init__(self, dry_run=False, backup_dir="/tmp/ubuntu-security-hardening-backups"):
        self.dry_run = dry_run
        self.backup_dir = backup_dir
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.changes_log = []

    def log(self, msg, level="INFO"):
        prefix = {
            "INFO": f"{Colors.OKBLUE}[INFO]{Colors.ENDC}",
            "SUCCESS": f"{Colors.OKGREEN}[SUCCESS]{Colors.ENDC}",
            "WARN": f"{Colors.WARNING}[WARN]{Colors.ENDC}",
            "FAIL": f"{Colors.FAIL}[FAIL]{Colors.ENDC}",
            "DRYRUN": f"{Colors.HEADER}[DRY-RUN]{Colors.ENDC}"
        }.get(level, "[INFO]")
        print(f"{prefix} {msg}")

    def run_cmd(self, cmd, sudo=True):
        full_cmd = f"sudo -n {cmd}" if sudo and os.geteuid() != 0 else cmd
        if self.dry_run:
            self.log(f"Would run command: {full_cmd}", "DRYRUN")
            return "Dry run", 0
        try:
            res = subprocess.run(full_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            return res.stdout.strip(), res.returncode
        except Exception as e:
            return str(e), -1

    def create_backup(self, file_path):
        if not os.path.exists(file_path):
            return None
        os.makedirs(self.backup_dir, exist_ok=True)
        filename = os.path.basename(file_path)
        backup_path = os.path.join(self.backup_dir, f"{filename}.bak_{self.timestamp}")
        if not self.dry_run:
            shutil.copy2(file_path, backup_path)
            self.log(f"Backup created for {file_path} -> {backup_path}", "INFO")
        else:
            self.log(f"Would backup {file_path} -> {backup_path}", "DRYRUN")
        return backup_path

    def harden_sysctl(self):
        self.log("Applying Sysctl Kernel Hardening Rules...", "INFO")
        src_config = os.path.join(os.path.dirname(__file__), "configs", "99-security-hardening.conf")
        dst_config = "/etc/sysctl.d/99-security-hardening.conf"
        
        self.create_backup(dst_config)
        if not self.dry_run:
            shutil.copy2(src_config, dst_config)
            out, code = self.run_cmd("sysctl -p /etc/sysctl.d/99-security-hardening.conf")
            if code == 0:
                self.log("Kernel sysctl parameters successfully hardened and reloaded.", "SUCCESS")
            else:
                self.log(f"Failed to reload sysctl: {out}", "WARN")
        else:
            self.log(f"Would copy {src_config} to {dst_config} and run sysctl -p", "DRYRUN")

    def harden_firewall(self):
        self.log("Configuring UFW Firewall...", "INFO")
        commands = [
            "ufw default deny incoming",
            "ufw default allow outgoing",
            "ufw allow 22/tcp",
            "ufw limit 22/tcp",
            "ufw --force enable"
        ]
        for cmd in commands:
            self.run_cmd(cmd)
        self.log("UFW Firewall configured with default deny incoming and SSH rate limiting.", "SUCCESS")

    def harden_accounts(self):
        self.log("Locking service accounts with interactive login shells...", "INFO")
        service_accounts = ['ftpuser', 'ftp']
        for user in service_accounts:
            if self.dry_run:
                self.log(f"Would check shell for account '{user}' and lock if interactive.", "DRYRUN")
                continue
            out, code = self.run_cmd(f"getent passwd {user}", sudo=False)
            if code == 0 and out:
                parts = out.split(":")
                if len(parts) >= 7:
                    shell = parts[6]
                    if shell not in ["/usr/sbin/nologin", "/bin/false"]:
                        self.run_cmd(f"usermod -s /usr/sbin/nologin {user}")
                        self.log(f"Service account '{user}' shell locked to /usr/sbin/nologin", "SUCCESS")
                    else:
                        self.log(f"Account '{user}' shell is already non-interactive ({shell}).", "INFO")

    def harden_file_permissions(self):
        self.log("Hardening critical file permissions...", "INFO")
        permissions_map = {
            "/etc/shadow": "0640",
            "/etc/gshadow": "0640",
            "/etc/passwd": "0644",
            "/etc/group": "0644",
            "/etc/sudoers": "0440"
        }
        for path, mode in permissions_map.items():
            if os.path.exists(path):
                self.create_backup(path)
                self.run_cmd(f"chmod {mode} {path}")
                self.run_cmd(f"chown root:root {path}")
        self.log("Critical file permissions updated.", "SUCCESS")

    def install_security_services(self):
        self.log("Installing and activating defense-in-depth security packages...", "INFO")
        packages = ["fail2ban", "auditd", "unattended-upgrades"]
        for pkg in packages:
            self.run_cmd(f"apt-get install -y {pkg}")
            self.run_cmd(f"systemctl enable --now {pkg}")
        
        jail_src = os.path.join(os.path.dirname(__file__), "configs", "fail2ban-jail.local")
        jail_dst = "/etc/fail2ban/jail.local"
        if os.path.exists(jail_src):
            self.create_backup(jail_dst)
            if not self.dry_run:
                shutil.copy2(jail_src, jail_dst)
                self.run_cmd("systemctl restart fail2ban")
        self.log("Security services (fail2ban, auditd, unattended-upgrades) deployed.", "SUCCESS")

    def harden_ssh(self):
        self.log("Configuring SSH Server Hardening...", "INFO")
        ssh_dir = "/etc/ssh/sshd_config.d"
        if os.path.exists("/etc/ssh"):
            src = os.path.join(os.path.dirname(__file__), "configs", "99-sshd-hardening.conf")
            dst = os.path.join(ssh_dir, "99-hardening.conf")
            self.create_backup(dst)
            if not self.dry_run:
                os.makedirs(ssh_dir, exist_ok=True)
                shutil.copy2(src, dst)
                self.run_cmd("systemctl reload sshd || systemctl reload ssh")
            else:
                self.log(f"Would copy {src} to {dst} and reload sshd service.", "DRYRUN")
            self.log("SSH hardening config applied at /etc/ssh/sshd_config.d/99-hardening.conf", "SUCCESS")
        else:
            self.log("SSH server not installed. Skipping SSH configuration.", "INFO")

    def run_all(self):
        self.log("=== Starting Ubuntu Security Hardening Engine ===", "HEADER")
        if self.dry_run:
            self.log("DRY-RUN MODE ENABLED: No system modifications will be made.", "WARN")
            
        self.harden_sysctl()
        self.harden_file_permissions()
        self.harden_accounts()
        self.harden_firewall()
        self.install_security_services()
        self.harden_ssh()
        
        self.log("=== Security Hardening Completed Successfully ===", "HEADER")

def main():
    hardener = SecurityHardener()
    hardener.run_all()

if __name__ == "__main__":
    main()
