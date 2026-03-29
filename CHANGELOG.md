# Changelog

All notable changes to ErisLite are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and the project uses [Semantic Versioning](https://semver.org/).

---

## [0.5.0] - 2025-07-04
### Added
- 🧑‍💻 Suspicious User Scan tool to detect UID 0 clones and hidden accounts
- 🔑 SSH Key Enumeration tool for auditing user `authorized_keys`
- 🟪 World-Writable File Scan with filtered and full modes
- 🧩 Kernel Module Inspection tool to flag unsigned or unexpected modules
- ⏱ Cron & Timer Inspection:
  - Parsed `/etc/cron*` and `/var/spool/cron`
  - Per-user `crontab -l` scans
  - Heuristic tagging (e.g., reverse shell, payload delivery)
- 🔐 Login/Auth Log Check:
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

## [0.4.0] – 2025-06-21

### Added
- ✅ Threat Sweep module now returns structured `status`, `details`, and `tags`
- ✅ Threat Insight Panel introduced with plain-English analyst descriptions
- ✅ Tags added to all major modules (integrity, users, kernel, listeners, etc.)
- ✅ Color-coded risk scoring system with a score out of 100
- ✅ Exported logs now include hostname, role, sweep profile, risk score, and tagged results

### Improved
- 🧠 Profile-based threat detection fully supported (`quick`, `standard`, `full`)
- 🧾 Friendly summary table with emoji indicators and status legend
- 📁 Log output is standardized and easy to parse for later tooling

### Compatibility
- Works in fully silent sweep mode or interactive CLI mode

---

## [0.3.0] - 2025-06-21
### Added
- 🔑 SSH Key Enumeration tool
- 📂 World-Writable File & Directory Scanner
- 🧩 Kernel Module Inspection utility
- ⏱️ Cron Job and systemd Timer anomaly checker
- 🚨 Integrated all above tools into `Threat Sweep` (Full profile)
- 📋 Color-coded status tags and summary panel for sweep results
- ↩️ Submenu navigation in Threat Sweep profile selector
- 📁 Auto-generating `user_profile.json` if missing
- 🔐 File lock on user profile for tamper protection
- ⌨️ Optional `KeyboardInterrupt` safety (pending toggle)

### Changed
- 🧭 Reorganized `security_menu.py` for clarity and scalability
- 🔧 Modularized long import lines in `security_menu.py` and `threat_sweep.py`
- 🧼 Cleaned up scan output to reduce noise (especially in sweep mode)

---

## [0.2.0] - 2025-06-16
### Added
- 🚨 Threat Sweep module with `quick`, `standard`, and `full` profiles
- 🧪 File Integrity Monitor and baseline mode
- 📡 Suspicious Listener Check
- 🕵️ Hidden/Suspicious User Account Scan
- 🖥️ Full Security Audit command combining major checks

### Changed
- 🖼️ Polished visual formatting using `rich` tables and headers
- ⌛ Added loading banners and better context in CLI menus

---

## [0.1.0] - 2025-06-02
### Added
- 🔧 Core CLI menu structure
- 📊 System info + snapshot
- 🌐 Port viewer
- 🌎 WHOIS & DNS tools
- 🧾 Log viewer (basic pagination)
- 🧱 Profile-based CLI identity system

---

## [0.0.9] - Pre-Alpha Internal Preview
### Added
- 🛠️ Initial CLI prototype
- 🧠 Early splash screen, and user config loading
