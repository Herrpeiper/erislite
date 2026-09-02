# Changelog

All notable changes to ErisLite are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and the project uses [Semantic Versioning](https://semver.org/).

---

## [1.1.0] - 2026-09-02

### Added
- New domain-based `erislite/` package structure replacing the legacy top-level `core/`, `tools/`, and `ui/` layout
- `erislite.config` package for centralized application settings, paths, logging, and theme configuration
- Centralized runtime path definitions for:
  - threat sweep logs
  - SOC Mode logs
  - network connection logs
  - integrity baselines
  - user runtime data
- Historical Threat Sweep logging under `data/logs/threat_sweeps/`
- Threat Sweep report viewer with:
  - recent sweep history
  - full per-module reports
  - profile metadata
  - normalized risk score display
  - threat tag summaries
- Structured detection reasons and status summaries across security modules
- Shared ErisLITE console instance for consistent Rich terminal rendering

### Changed
- Refactored application modules into domain packages:
  - `erislite.accounts`
  - `erislite.containers`
  - `erislite.network`
  - `erislite.persistence`
  - `erislite.response`
  - `erislite.sweep`
  - `erislite.system`
  - `erislite.ui`
  - `erislite.vulnerability`
- Rapid Response split from a single large module into:
  - `menu.py`
  - `triage.py`
  - `actions.py`
  - `undo.py`
  - `utils.py`
- Redesigned terminal UI across the application with a consistent cyan ErisLITE visual language
- Replaced legacy centered tables, emoji-heavy status output, and magenta styling with compact Rich panels and tables
- Standardized global return prompt to `[ENTER] Return to menu`
- `erislite/version.py` is now the single source of truth for application version metadata
- `erislite.config.settings.APP_VERSION` now derives from `erislite.version.VERSION`
- Threat Sweep profiles are now centralized in `erislite.config.settings.SWEEP_PROFILES`
- Threat Sweep risk scoring now preserves the full weighted score instead of capping the raw score at 100
- Sweep logs now store:
  - raw risk score
  - maximum possible score
  - percentage rating
  - profile
  - hostname
  - tags
  - per-module results
- File Integrity baseline metadata now records monitored, recorded, and unavailable files
- SSH Key Check now treats normal user authorized keys as informational and flags only unusual placement or key formats
- SSH key display now uses SHA-256 fingerprints instead of truncated raw public keys
- SSH Config Audit now distinguishes explicit secure, insecure, and unset directives
- SUID/SGID Scan now reports known-safe and review-required privileged binaries separately
- World-Writable Check now focuses filtered scans on persistence- and execution-sensitive paths
- Cron / Timer Check now parses system crontabs, user crontabs, periodic scripts, and systemd timers according to their actual formats
- Hosts Tamper Check now uses IP-aware analysis for private, loopback, and duplicate mappings
- Backdoor Detection now separates persistence findings from collection/read errors
- Docker Security Check now distinguishes unavailable Docker inspection from a valid zero-container result
- Kernel Module Check now reports unavailable `lsmod` support instead of treating an empty collection as clean

### Fixed
- Threat Sweep log writer and viewer now use the same directory, filename convention, and result schema
- SUID/SGID result is correctly included in Threat Sweep scoring
- Kernel module inspection no longer reports a false clean result when `lsmod` is unavailable
- File Integrity no longer treats an incomplete-but-accounted-for baseline as tampered
- Fixed File Integrity baseline modification-time false positives
- World-Writable Scan no longer produces thousands of low-value findings from broad `/opt` trees such as Conda installations
- SUID/SGID known-safe baseline expanded for common Linux privileged helpers
- Cron scanner no longer flags legitimate `apt-config` use of `eval` as encoded execution
- Cron parser now handles the username field in `/etc/crontab` and `/etc/cron.d/*`
- Periodic cron directories are now scanned as executable scripts rather than crontab syntax
- SSH Config silent mode and interactive mode now use consistent findings
- Root shell detection now requires an actual terminal session rather than flagging non-interactive shell wrappers
- Process anomaly scan no longer treats ordinary privileged shell/interpreter wrappers as automatically suspicious
- Listener detection no longer treats high-numbered ports alone as suspicious
- User anomaly detection no longer flags normal non-login service accounts for missing home directories or shells
- `/etc/hosts` loopback mappings are no longer automatically treated as malicious
- Docker CLI or daemon unavailability no longer appears as a clean Docker result
- Empty Threat Sweep report panels now display `No issues detected.` instead of rendering blank

### Removed
- Legacy runtime dependencies on the old `core/`, `tools/`, and top-level `ui/` package structure
- Duplicate hardcoded application version strings
- Duplicate Threat Sweep profile definitions
- Hardcoded ErisLITE runtime paths spread across individual modules
- Legacy Rapid Response monolithic implementation
- Environment-specific or overly broad heuristics that generated excessive false positives

---

## [1.0.0] - 2026-04-05

### Added
- `tools/backdoor_check.py` — shell init files, profile.d, LD_PRELOAD persistence indicators
- `tools/hosts_check.py` — /etc/hosts entries that redirect critical domains or look malicious
- `tools/process_check.py` — root processes from suspicious paths, deleted executables, bad tool names
- `tools/rapid_response.py` — triage scan with dry-run and live containment modes
- `infra/systemd/erislite-agent.service` — systemd unit file for running ErisLITE as a managed service

### Changed
- `tools/suid_check.py` — whitelist expanded to cover common legitimate SUID/SGID binaries; findings now include per-binary path and reason
- `core/version.py` — version bumped to 1.0.0
- README updated for stable release

### Fixed
- `tools/suid_check.py` — silent mode now returns full binary list in `details` instead of a count string
- Status badge updated from `beta` to `stable`

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