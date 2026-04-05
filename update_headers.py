"""
Patches the # Project/Module/Version/Last Updated header block
in every ErisLITE Python source file listed below.
Run from the ErisLITE repo root: python3 update_headers.py
"""

import re
from pathlib import Path

TODAY = "2026-04-05"
VERSION = "1.0"

# (relative_path, module_name, description)
FILES = [
    # core
    ("core/version.py",         "version.py",           "Single source of truth for version string and build date."),
    ("core/user_profile.py",    "user_profile.py",      "Manages user_profile.json: creation, locking, and forward-migration of missing fields."),
    ("core/network_scan.py",    "network_scan.py",      "Network listener scan using 'ss'; risk classification by port and process."),
    ("core/login_audit.py",     "login_audit.py",       "Login and auth audit: failed logins, root shells, recent login history."),
    ("core/cve_checker.py",     "cve_checker.py",       "Offline CVE version check for kernel, sudo, and glibc."),
    ("core/security_audit.py",  "security_audit.py",    "Snapshot-style security posture check: firewall, SSH keys, world-writable, failed logins."),
    ("core/log_viewer.py",      "log_viewer.py",        "Snapshot log viewer: browse and display saved snapshot logs."),
    ("core/cve_tools.py",       "cve_tools.py",         "Offline CVE search tool against a local JSON cache."),
    ("core/system_info.py",     "system_info.py",       "System information display: OS, CPU, RAM, uptime, logged-in users."),
    ("core/network_tools.py",   "network_tools.py",     "Network utility tools: IPs, gateway, DNS, ping, traceroute, WHOIS, connections."),
    ("core/port_scan.py",       "port_scan.py",         "TCP port scanner: scans common ports, identifies services, generates reports."),
    # tools
    ("tools/snapshot.py",           "snapshot.py",              "Captures a system snapshot to a timestamped log file in data/logs/."),
    ("tools/threat_sweep.py",       "threat_sweep.py",          "Threat sweep orchestrator: runs selected modules, scores risk, saves results."),
    ("tools/integrity_tools.py",    "integrity_tools.py",       "File integrity monitor: SHA-256 baseline creation and change detection."),
    ("tools/listener_check.py",     "listener_check.py",        "Heuristic suspicious network listener detection."),
    ("tools/user_anomaly.py",       "user_anomaly.py",          "Suspicious user account scan: UID 0 clones, bad shells, hidden accounts."),
    ("tools/kernel_module_check.py","kernel_module_check.py",   "Kernel module inspection: known-bad names, untracked modules, unusual paths."),
    ("tools/ssh_key_check.py",      "ssh_key_check.py",         "SSH authorized_keys enumeration across all user home directories."),
    ("tools/ssh_config_check.py",   "ssh_config_check.py",      "sshd_config audit against secure defaults."),
    ("tools/world_writable_check.py","world_writable_check.py", "World-writable file and directory scan in critical filesystem paths."),
    ("tools/cron_timer_check.py",   "cron_timer_check.py",      "Cron job and systemd timer inspection for suspicious scheduled tasks."),
    ("tools/suid_check.py",         "suid_check.py",            "SUID/SGID binary scan: flags unexpected or dangerous binaries."),
    ("tools/docker_check.py",       "docker_check.py",          "Docker security check: privileged containers and exposed sockets."),
    ("tools/firewall_check.py",     "firewall_check.py",        "Firewall status check: UFW, firewalld, nftables, iptables."),
    ("tools/security_log.py",       "security_log.py",          "Security audit log writer: saves findings to data/logs/."),
    ("tools/sweep_viewer.py",       "sweep_viewer.py",          "Threat sweep log viewer: browse and inspect past sweep results."),
    ("tools/soc_mode.py",           "soc_mode.py",              "SOC Mode: 15-minute rolling log snapshot and posture assessment."),
    # agent
    ("agent/agent_loop.py",     "agent_loop.py",        "HTTP polling agent loop: registers, heartbeats, polls jobs, submits results."),
    ("agent/agent_ws_loop.py",  "agent_ws_loop.py",     "WebSocket agent loop: lower-latency alternative to the HTTP polling loop."),
    ("agent/basalt_client.py",  "basalt_client.py",     "HTTP client for all Basalt Controller communication."),
    ("agent/dispatcher.py",     "dispatcher.py",        "Routes controller jobs to ErisLITE modules via MODULE_MAP."),
    ("agent/job_worker.py",     "job_worker.py",        "Compatibility shim — delegates to agent_loop.run()."),
    # ui
    ("ui/cli.py",               "cli.py",               "Main CLI menu loop."),
    ("ui/splash.py",            "splash.py",            "Startup splash screen with system profile and version info."),
    ("ui/utils.py",             "utils.py",             "Shared UI utilities: clear_screen, show_header, pause_return, get_os."),
    ("ui/menus/security_menu.py",   "security_menu.py", "Security tools menu with last-sweep dashboard panel."),
    ("ui/menus/help_menu.py",       "help_menu.py",     "Help / About panel."),
    ("ui/menus/system_menu.py",     "system_menu.py",   "System info menu."),
    ("ui/menus/network_menu.py",    "network_menu.py",  "Network tools menu."),
    ("ui/menus/cve_tools_menu.py",  "cve_tools_menu.py","CVE tools menu."),
    ("ui/menus/sweep_viewer.py",    "sweep_viewer.py",  "Sweep log viewer menu."),
]

HEADER_PATTERN = re.compile(
    r'^(# Project:.*?\n)?'
    r'(# Module:.*?\n)?'
    r'(# Author:.*?\n)?'
    r'(# Version:.*?\n)?'
    r'(# License:.*?\n)?'
    r'(# Created:.*?\n)?'
    r'(# Last Updated:.*?\n)?'
    r'(# Description:.*?\n(?:#.*?\n)*)?',
    re.MULTILINE
)

def make_header(module_name, description):
    return (
        f"# Project: ErisLITE\n"
        f"# Module: {module_name}\n"
        f"# Author: Liam Piper-Brandon\n"
        f"# Version: {VERSION}\n"
        f"# License: MIT\n"
        f"# Created: 2025-06-01\n"
        f"# Last Updated: {TODAY}\n"
        f"# Description: {description}\n"
    )

updated = []
skipped = []

for rel_path, module_name, description in FILES:
    path = Path(rel_path)
    if not path.exists():
        skipped.append(rel_path)
        continue

    content = path.read_text(encoding="utf-8")
    new_header = make_header(module_name, description)

    # If file already has a header block, replace it
    match = HEADER_PATTERN.match(content)
    if match and match.group(0).strip():
        new_content = new_header + content[match.end():]
    else:
        # Prepend header, preserving any shebang or future-annotations line
        if content.startswith("from __future__") or content.startswith("#!"):
            first_line_end = content.index("\n") + 1
            new_content = content[:first_line_end] + "\n" + new_header + content[first_line_end:]
        else:
            new_content = new_header + "\n" + content

    path.write_text(new_content, encoding="utf-8")
    updated.append(rel_path)

print(f"\nUpdated {len(updated)} files:")
for f in updated:
    print(f"  ✓ {f}")

if skipped:
    print(f"\nSkipped {len(skipped)} files (not found):")
    for f in skipped:
        print(f"  - {f}")