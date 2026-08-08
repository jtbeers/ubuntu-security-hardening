# 🛡️ Ubuntu Security Hardening Engine (`ubuntu-security-hardening`)

An automated security hardening, kernel sysctl tuning, firewall configuration, account locking, and intrusion prevention tool for **Ubuntu Linux** (24.04 LTS Noble Numbat & compatible releases).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Ubuntu 24.04](https://img.shields.io/badge/Ubuntu-24.04_LTS-orange.svg)](https://ubuntu.com)

---

## 📌 Features

- ⚙️ **Kernel Sysctl Hardening**: Automatically applies production-grade sysctl settings (`/etc/sysctl.d/99-security-hardening.conf`), enforcing ASLR, strict RP filtering, TCP SYN cookie DoS protection, dmesg restriction, and disabling ICMP redirects & IP forwarding.
