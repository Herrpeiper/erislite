# ErisLITE

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-beta-orange)

*A modular security monitoring and analysis toolkit with a centralised agent-controller architecture.*

ErisLITE is a cybersecurity utility designed for analysts, students, and system administrators. It provides a local CLI for interactive security auditing, and a Basalt Controller that aggregates results from multiple remote agents via a web dashboard.

---

## Overview

ErisLITE has two modes of operation:

**Standalone CLI** — run directly on any Linux host for interactive security checks, threat sweeps, and snapshot logging. No other software required.

**Agent mode** — deploy ErisLITE alongside the Basalt Controller (a separate project). ErisLITE's `agent/` subsystem registers with the controller, receives job dispatch commands, executes the appropriate modules, and returns structured results. The Basalt Controller provides the web dashboard, job queue, and multi-agent visibility.

The two projects are fully independent — ErisLITE works without Basalt, and Basalt can work with any agent that speaks its protocol.

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

### Basalt Controller (separate project)

The Basalt Controller is a separate application that ErisLITE can connect to as an agent. It provides a FastAPI backend, WebSocket hub, SQLite result store, and a React web dashboard for managing multiple ErisLITE agents from one place.

See the [Basalt Controller repository](https://github.com/herrpeiper/basalt-controller) for its own setup instructions.

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

### Standalone CLI

```bash
sudo python3 main.py
```

Typical workflow:
1. Launch ErisLITE
2. Select **Security Tools** from the main menu
3. Run individual checks or select **Run Threat Sweep**
4. Review findings and risk score
5. Open **View Recent Threat Sweeps** to review past results

### Running as a Basalt Agent

If you have a Basalt Controller running elsewhere, ErisLITE can connect to it as an agent:

```bash
export BASALT_CONTROLLER_URL=http://<controller-ip>:8000
export BASALT_AGENT_KEY=<your-key>
python3 -m agent.agent_loop
```

Once connected, the controller can dispatch any of the 14 security modules to this host remotely and view results in the web dashboard.

See the [Basalt Controller repository](https://github.com/herrpeiper/basalt-controller) for controller setup instructions.

---

## Project Structure

```
ErisLITE/
│
├── agent/                   # Basalt agent subsystem
│   ├── agent_loop.py        # HTTP polling agent loop
│   ├── agent_ws_loop.py     # WebSocket agent loop
│   ├── basalt_client.py     # Controller HTTP client
│   └── dispatcher.py        # Routes controller jobs to modules
│
├── core/                    # Core system utilities
│   ├── network_scan.py      # Raw network listener data
│   ├── login_audit.py       # Auth log checks
│   ├── cve_checker.py       # CVE version matching
│   ├── security_audit.py    # Snapshot-style audit checks
│   ├── user_profile.py      # Profile load/create
│   └── version.py           # Version constant
│
├── tools/                   # Security scan modules
│   ├── threat_sweep.py      # Sweep orchestrator
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
├── ui/                      # CLI interface
│   ├── cli.py               # Main menu loop
│   ├── splash.py            # Startup screen
│   └── menus/               # Submenu modules
│
├── data/
│   └── logs/                # Sweep and snapshot logs (gitignored)
│
├── main.py                  # CLI entry point
├── requirements.txt         # Python dependencies
└── README.md
```

---

## First Run Notes

**Integrity baseline** — the File Integrity module requires a baseline before it can detect changes. On first run, go to Security Tools → File Integrity Monitor → Create Integrity Baseline. The baseline is stored in `data/integrity/` and is gitignored by design.

**User profile** — `user_profile.json` is auto-generated on first launch and locked read-only. To suppress snapshot alerts for known users, add usernames to the `known_users` list in the profile (you'll need to temporarily `chmod 644` it first).

**Root access** — some modules (kernel modules, world-writable scan, SUID scan, auth logs) require root to return complete results. Run with `sudo` for full coverage.

---

## Development

ErisLITE is designed for modular extension. Adding a new security module:

1. Create `tools/my_check.py` with a `run_my_check(silent=False)` function that returns `{"status": ..., "details": [...], "tags": [...]}`
2. Add it to the `security_menu.py` menu
3. Add it to the `profiles` dict in `tools/threat_sweep.py`
4. Add it to `agent/dispatcher.py` MODULE_MAP to make it available remotely

---

## License

MIT License — see `LICENSE` for details.

---

## Author

Liam Piper-Brandon (Stackdefender)

---

## Disclaimer

This software is provided for educational and research purposes. Users are responsible for ensuring that the software is used in compliance with applicable laws, system policies, and authorization requirements.