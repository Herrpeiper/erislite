# ErisLITE

<p align="center">
  <img src="assets/image/erislite_banner.png" alt="ErisLITE" width="600"/>
</p>

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-stable-green)
![Version](https://img.shields.io/badge/version-1.1.0-blue)

*A modular Linux security monitoring and triage toolkit for analysts, students, and system administrators.*

ErisLITE is a standalone CLI toolkit for interactive security auditing, host triage, and competition-focused incident response on Linux systems.

Run threat sweeps, inspect system configuration, review historical findings, capture host snapshots, and perform rapid-response actions without requiring external infrastructure or cloud services.

ErisLITE is designed primarily for CCDC-style competition environments, cybersecurity students, analysts, and administrators who need fast, readable, local-first host visibility.

---

## Features

### Security Checks

| Module | What it checks |
|--------|----------------|
| Posture Snapshot | High-level security posture and host exposure |
| Network Listeners | Active TCP/UDP listeners with contextual risk classification |
| User Account Scan | UID anomalies, shell configuration, suspicious accounts |
| Login / Auth Logs | Failed logins, interactive root shells, recent login activity |
| Kernel Modules | Known-bad, unresolved, or unusually located kernel modules |
| File Integrity | SHA-256 baseline validation for monitored critical files |
| World-Writable Files | Writable execution and persistence paths in sensitive locations |
| SUID / SGID | Unexpected privileged executables and risky locations |
| Cron / Timers | Suspicious cron jobs, periodic scripts, and systemd timer services |
| SSH Config Audit | Explicit `sshd_config` settings against the ErisLITE hardening baseline |
| SSH Key Check | Authorized key enumeration and privileged-account key review |
| Hosts Tamper Check | Suspicious `/etc/hosts` redirects and hostname mappings |
| Process Anomaly Scan | Suspicious execution paths, deleted binaries, and process indicators |
| Docker Security | Privileged containers, sensitive mounts, and Docker socket exposure |
| Firewall Status | UFW, firewalld, nftables, and iptables state |
| CVE Version Check | Offline software-version matching against the local CVE cache |
| Backdoor Detection | Shell init, profile, and `LD_PRELOAD` persistence indicators |

### Threat Sweep

Threat Sweep combines selected modules into structured security profiles:

| Profile | Scope |
|---------|-------|
| `quick` | Listeners, users, authentication |
| `standard` | Integrity, listeners, users, authentication, CVE checks |
| `full` | Full host security and persistence assessment |

Threat Sweep provides:

- weighted risk scoring relative to the selected profile
- per-module status and findings
- threat tags with analyst-oriented explanations
- top risk contributors
- historical JSON logging
- full report viewing from previous sweeps

Risk is displayed relative to the checks that actually ran. For example:

```text
Score: 30/95
Rating: 32%
Risk Level: Moderate
```

### Additional Tools

| Tool | What it does |
|------|--------------|
| System Snapshot | Captures host, network, routing, and posture information to a timestamped log |
| Snapshot Log Viewer | Reviews previously captured system snapshots |
| Sweep Log Viewer | Browses recent Threat Sweeps and full per-module reports |
| SOC Mode | Repeated host posture collection for short-duration monitoring |
| Rapid Response | Triage, dry-run containment, live response actions, and rollback support |
| CVE Tools | Offline CVE search against the local cache |

### CLI

- Interactive Rich-based terminal interface
- Section-grouped security tools
- Threat Sweep with `quick`, `standard`, and `full` profiles
- Weighted risk scoring relative to the checks executed
- Per-module findings and threat insights
- Historical Threat Sweep logging and report viewing
- System snapshot logging
- SOC Mode rolling posture collection
- Consistent `[ENTER] Return to menu` navigation

---

## Requirements

- Python 3.9+
- Linux (all security modules are Linux-only — Windows and macOS are not supported)
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
├── erislite/
│   │
│   ├── accounts/
│   │   ├── profile.py
│   │   ├── login_audit.py
│   │   ├── users.py
│   │   ├── ssh_keys.py
│   │   └── ssh_config.py
│   │
│   ├── config/
│   │   ├── settings.py
│   │   ├── theme.py
│   │   └── logging.py
│   │
│   ├── containers/
│   │   └── docker.py
│   │
│   ├── network/
│   │   ├── scan.py
│   │   ├── tools.py
│   │   ├── ports.py
│   │   ├── listeners.py
│   │   ├── firewall.py
│   │   └── hosts.py
│   │
│   ├── persistence/
│   │   ├── cron.py
│   │   ├── suid.py
│   │   ├── world_writable.py
│   │   └── backdoors.py
│   │
│   ├── response/
│   │   ├── security_log.py
│   │   └── rapid_response/
│   │       ├── menu.py
│   │       ├── triage.py
│   │       ├── actions.py
│   │       ├── undo.py
│   │       └── utils.py
│   │
│   ├── sweep/
│   │   ├── threat_sweep.py
│   │   ├── viewer.py
│   │   ├── snapshot.py
│   │   ├── log_viewer.py
│   │   └── soc_mode.py
│   │
│   ├── system/
│   │   ├── info.py
│   │   ├── processes.py
│   │   ├── kernel_modules.py
│   │   ├── integrity.py
│   │   └── security_audit.py
│   │
│   ├── ui/
│   │   ├── console.py
│   │   ├── utils.py
│   │   ├── splash.py
│   │   ├── cli.py
│   │   └── menus/
│   │       ├── security_menu.py
│   │       ├── network_menu.py
│   │       ├── system_menu.py
│   │       ├── cve_tools_menu.py
│   │       └── help_menu.py
│   │
│   ├── vulnerability/
│   │   ├── cve_checker.py
│   │   └── cve_tools.py
│   │
│   └── version.py
│
├── data/
│   ├── integrity/
│   └── logs/
│       ├── threat_sweeps/
│       ├── soc_mode/
│       └── network_connections/
│
├── infra/
│   └── systemd/
│       └── erislite-agent.service
│
├── assets/
├── main.py
├── requirements.txt
├── CHANGELOG.md
├── LICENSE
└── README.md
```

---

## First Run Notes

**Integrity baseline** — File Integrity requires a baseline before it can detect changes. On first run, go to **Security Tools → File Integrity → Create Integrity Baseline**. Runtime integrity data is stored under `data/integrity/` and is gitignored by design.

ErisLITE records which monitored files were successfully hashed and which were unavailable. Protected files may require root privileges, but unavailable files do not automatically invalidate a correctly recorded baseline.

**User profile** — ErisLITE maintains user and host profile information used by portions of the CLI and snapshot tooling. Runtime user data is stored under `~/.erislite/`.

**Root access** — some checks require elevated privileges for complete results, including authentication logs, kernel modules, SUID/SGID inspection, protected integrity targets, process inspection, and portions of persistence scanning. Run with `sudo` when full host coverage is required.

**CVE version checker** — performs offline version matching against the local CVE cache. A version match does not confirm a vulnerability. Vendors frequently backport fixes without changing the upstream version string. Always verify findings against vendor advisories.

**Threat Sweep history** — historical sweeps are stored under `data/logs/threat_sweeps/`. The latest sweep summary is also stored at `~/.erislite/last_sweep.json`.

**Rapid Response live mode** — Rapid Response includes dry-run and live containment actions. Live mode can modify system state, terminate processes, change firewall behavior, and perform other containment actions. Review dry-run output before executing live actions.

---

## Development

ErisLITE uses a domain-oriented package structure. New modules should be placed in the appropriate package under `erislite/`.

A security check should support structured non-interactive results:

```python
def run_my_check(silent: bool = False) -> dict:
    return {
        "status": "ok",
        "details": [],
        "tags": [],
    }
```
---

## License

MIT License — see `LICENSE` for details.

---

## Author

Liam Piper-Brandon (Stackdefender)

---

## Disclaimer

ErisLITE is intended for use on systems you own or have explicit written authorisation to audit. Unauthorised use against systems you do not own or have permission to test is illegal and unethical. The author accepts no responsibility for misuse.

The CVE version checker performs offline version matching only. A version match does not confirm a vulnerability — vendors frequently backport patches without changing the base version number. Do not treat a match as a confirmed finding without verifying against vendor advisories.

Rapid Response includes live containment functionality that can modify system state or disrupt services. Always review dry-run output first. Use live actions only on systems you are authorised to modify and only when you understand the actions being performed.

This software is provided as-is with no warranty of any kind. The author accepts no liability for damages, data loss, or service disruption resulting from its use.
