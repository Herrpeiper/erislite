# ErisLITE

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-stable-green)

*A modular Linux security monitoring toolkit for analysts, students and system administrators.*

ErisLITE is a standalone CLI tool for interactive security auditing on Linux hosts. Run threat sweeps, inspect system configuration, and review findings — no external dependencies or infrastructure required.

---

## Features

### Security Modules (14 total)

| Module | What it checks |
|--------|---------------|
| Network Listeners | Active TCP/UDP listeners with risk classification |
| Listener Check | Heuristic suspicious-listener detection |
| User Anomaly Scan | UID 0 clones, hidden accounts, bad shells |
| Login / Auth Logs | Failed logins, root shells, auth anomalies |
| Kernel Modules | Known-bad or untracked kernel modules |
| Cron & Timers | Suspicious scheduled tasks and systemd timers |
| CVE Version Check | Kernel / sudo / glibc version matches |
| SSH Keys | Enumerates `authorized_keys` across all users |
| SSH Config Audit | `sshd_config` settings against secure defaults |
| World-Writable | World-writable files and dirs in critical paths |
| SUID / SGID | Unexpected SUID/SGID binaries |
| Docker Security | Privileged containers and exposed sockets |
| Firewall Status | UFW / iptables presence and rule state |
| File Integrity | SHA-256 baseline check on critical system files |

### CLI
- Interactive menu system with section-grouped security tools
- Threat Sweep with `quick`, `standard`, and `full` profiles
- Risk scoring (0–100) with colour-coded results and threat insight panel
- System snapshot logging to `data/logs/`
- Sweep log viewer with previous result browsing
- SOC Mode: 15-minute rolling log snapshot

---

## Requirements

- Python 3.9+
- Linux (most security modules are Linux-only)
- `sudo` / root access recommended for full scan coverage
```bash
pip install -r requirements.txt
```

---

## Installation
```bash
git clone https://github.com/herrpeiper/ErisLITE.git
cd ErisLITE
pip install -r requirements.txt
```

---

## Usage
```bash
sudo python3 main.py
```

Typical workflow:
1. Launch ErisLITE
2. Select **Security Tools** from the main menu
3. Run individual checks or select **Run Threat Sweep**
4. Review findings and risk score
5. Open **View Recent Threat Sweeps** to review past results

---

## Project Structure
```
ErisLITE/
│
├── core/                    
│   ├── network_scan.py      
│   ├── login_audit.py       
│   ├── cve_checker.py       
│   ├── security_audit.py    
│   ├── user_profile.py      
│   └── version.py           
│
├── tools/                   
│   ├── threat_sweep.py      
│   ├── listener_check.py
│   ├── user_anomaly.py
│   ├── integrity_tools.py
│   ├── kernel_module_check.py
│   ├── ssh_key_check.py
│   ├── ssh_config_check.py
│   ├── world_writable_check.py
│   ├── cron_timer_check.py
│   ├── suid_check.py
│   ├── docker_check.py
│   ├── firewall_check.py
│   └── snapshot.py
│
├── ui/                      
│   ├── cli.py               
│   ├── splash.py            
│   └── menus/               
│       ├── security_menu.py 
│       ├── network_menu.py  
│       ├── system_menu.py   
│       ├── cve_tools_menu.py
│       └── help_menu.py     
│
├── data/
│   └── logs/                
│
├── main.py                  
├── requirements.txt         
└── README.md
```

---

## First Run Notes

**Integrity baseline** — the File Integrity module requires a baseline before it can detect changes. On first run, go to Security Tools → File Integrity Monitor → Create Integrity Baseline. The baseline is stored in `data/integrity/` and is gitignored by design.

**User profile** — `user_profile.json` is auto-generated on first launch and locked read-only. To suppress snapshot alerts for known users, add usernames to the `known_users` list in the profile (you'll need to temporarily `chmod 644` it first).

**Root access** — some modules (kernel modules, world-writable scan, SUID scan, auth logs) require root to return complete results. Run with `sudo` for full coverage.

**Known limitations** — security modules are Linux-only. Windows and macOS are not supported. Some checks may return partial results without root access.

---

## Development

ErisLITE is designed for modular extension. Adding a new security module:

1. Create `tools/my_check.py` with a `run_my_check(silent=False)` function that returns `{"status": ..., "details": [...], "tags": [...]}`
2. Add it to the `security_menu.py` menu
3. Add it to the `profiles` dict in `tools/threat_sweep.py`

---

## License

MIT License — see `LICENSE` for details.

---

## Author

Liam Piper-Brandon (Stackdefender)

---

## Disclaimer

This software is provided for educational and research purposes. Users are responsible for ensuring that the software is used in compliance with applicable laws, system policies, and authorization requirements.