# Changelog

All notable changes to ErisLite are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and the project uses [Semantic Versioning](https://semver.org/).

---

## [0.7.0] - 2026-03-29

### Added
- `agent/` subsystem — allows ErisLITE to operate as a remote agent for the Basalt Controller
  - `agent_loop.py` — registers with controller, sends heartbeats, polls for jobs, submits results
  - `agent_ws_loop.py` — WebSocket-based equivalent for lower-latency deployments
  - `basalt_client.py` — HTTP client handling all controller communication
  - `dispatcher.py` — routes incoming jobs to ErisLITE modules; all 14 security modules wired up with a consistent `_wrap()` response envelope
- `dispatcher.py` module map covers: `network.listeners`, `security.listeners`, `security.users`, `security.kernel`, `security.ssh_keys`, `security.ssh_config`, `security.world_writable`, `security.cron`, `security.suid`, `security.docker`, `security.firewall`, `security.integrity`, `security.login`, `security.cve`

### Fixed
- `agent_loop.py`, `agent_ws_loop.py`, `job_worker.py` — hardcoded `AGENT_ID = "erislite-legion"` replaced with dynamic resolution: env var → `user_profile.json` → hostname fallback
- `basalt_client.py` — `register()` now pulls `segment` and `role` from `user_profile.json` instead of hardcoding `"default"` / `"workstation"`
- `job_worker.py` — hardcoded controller URL replaced with env var; file reduced to a compatibility shim delegating to `agent_loop.run()`
- `dispatcher.py` — `sys.path` fix added so ErisLITE modules resolve correctly regardless of the directory the agent process is launched from
- `agent_loop.py` — `tuple[float, float, int]` return hint replaced with `Tuple` from `typing` for Python 3.9 compatibility

---

## [0.6.0] - 2026-03-29

### Added
- `core/version.py` — single source of truth for version string and build date; imported by `splash.py` and `help_menu.py`
- `known_users` field in `user_profile.json` — snapshot user recognition driven by profile instead of hardcoded names

### Fixed
- `tools/snapshot.py` — removed hardcoded personal username whitelist (`{"mar", "admin", "erislite"}`); whitelist now populated from `profile["known_users"]`; fixed cut-off module docstring
- `core/user_profile.py` — `print()` replaced with `console.print()` so Rich markup renders correctly on profile creation
- `tools/suid_check.py` — expanded filesystem walk exclusions to match `world_writable_check.py` (`/snap`, `/var/lib/docker`, `/run`, etc.); prunes dirs in-place to avoid slow scans
- `tools/threat_sweep.py` — `suid` result now correctly wired into the `results` dict so SUID findings contribute to the risk score; `quick` sweep profile expanded from listeners-only to include `users` and `login`
- `core/cve_tools.py` — actionable guidance printed when cache is missing or empty
- `ui/cli.py` — main menu uses `Prompt.ask()` instead of bare `input()` for consistent UX
- `ui/splash.py`, `ui/menus/help_menu.py` — version strings pulled from `core.version` instead of hardcoded literals
- `tools/security_log.py` — `list[str]` type hint replaced with `List[str]` for Python 3.9 compatibility
- `data/integrity/baseline.json`, `config/user_profile.json` — removed from repository; added to `.gitignore`
- `.gitignore` — added rules for `data/integrity/`, `data/logs/`, `data/cve/`, `.erislite/`, `user_profile.json`

### Changed
- `ui/menus/security_menu.py` — replaced `Table(box=None)` menu layout with `console.print()` lines using fixed key-column width for consistent alignment; removed emojis that rendered as broken glyphs; removed redundant label annotations; hotkey bar separated from rule characters to prevent terminal strikethrough rendering artefact
- `tools/threat_sweep.py` — `quick` profile description updated to reflect expanded checks; sweep submenu labels updated

---

## [0.5.0] - 2025-07-04

### Added
- Suspicious User Scan tool to detect UID 0 clones and hidden accounts
- SSH Key Enumeration tool for auditing user `authorized_keys`
- World-Writable File Scan with filtered and full modes
- Kernel Module Inspection tool to flag unsigned or unexpected modules
- Cron & Timer Inspection:
  - Parsed `/etc/cron*` and `/var/spool/cron`
  - Per-user `crontab -l` scans
  - Heuristic tagging (e.g., reverse shell, payload delivery)
- Login/Auth Log Check:
  - Failed login attempt detection
  - UID 0 shell detection
  - Recent login summary

### Enhanced
- Integrated all tools into Threat Sweep system with risk scoring
- Color-coded sweep summary with status indicators and threat insights

### Notes
- All tools compatible with `silent=True` mode for non-interactive sweep use
- All output routed through Rich-based display for readability

---

## [0.4.0] - 2025-06-21

### Added
- Threat Sweep module now returns structured `status`, `details`, and `tags`
- Threat Insight Panel introduced with plain-English analyst descriptions
- Tags added to all major modules (integrity, users, kernel, listeners, etc.)
- Color-coded risk scoring system with a score out of 100
- Exported logs now include hostname, role, sweep profile, risk score, and tagged results

### Improved
- Profile-based threat detection fully supported (`quick`, `standard`, `full`)
- Friendly summary table with emoji indicators and status legend
- Log output is standardized and easy to parse for later tooling

### Compatibility
- Works in fully silent sweep mode or interactive CLI mode

---

## [0.3.0] - 2025-06-21

### Added
- SSH Key Enumeration tool
- World-Writable File & Directory Scanner
- Kernel Module Inspection utility
- Cron Job and systemd Timer anomaly checker
- Integrated all above tools into Threat Sweep (Full profile)
- Color-coded status tags and summary panel for sweep results
- Submenu navigation in Threat Sweep profile selector
- Auto-generating `user_profile.json` if missing
- File lock on user profile for tamper protection

### Changed
- Reorganized `security_menu.py` for clarity and scalability
- Modularized long import lines in `security_menu.py` and `threat_sweep.py`
- Cleaned up scan output to reduce noise (especially in sweep mode)

---

## [0.2.0] - 2025-06-16

### Added
- Threat Sweep module with `quick`, `standard`, and `full` profiles
- File Integrity Monitor and baseline mode
- Suspicious Listener Check
- Hidden/Suspicious User Account Scan
- Full Security Audit command combining major checks

### Changed
- Polished visual formatting using `rich` tables and headers
- Added loading banners and better context in CLI menus

---

## [0.1.0] - 2025-06-02

### Added
- Core CLI menu structure
- System info and snapshot
- Port viewer
- WHOIS & DNS tools
- Log viewer with basic pagination
- Profile-based CLI identity system

---

## [0.0.9] - Pre-Alpha Internal Preview

### Added
- Initial CLI prototype
- Early splash screen and user config loading