"""
ErisLITE header updater.

Updates the standard source header in current ErisLITE Python modules.

Run from the repository root:

    python3 update_headers.py
"""

import re
from pathlib import Path

from erislite.version import VERSION


TODAY = "2026-09-02"


FILES = [
    (
        "main.py",
        "main.py",
        "ErisLITE entry point — initializes user profile and launches the CLI.",
    ),

    # ---------------------------------------------------------------------
    # Accounts
    # ---------------------------------------------------------------------
    (
        "erislite/accounts/profile.py",
        "profile.py",
        "Manages user profile creation, locking, and migration.",
    ),
    (
        "erislite/accounts/login_audit.py",
        "login_audit.py",
        "Login and authentication audit: failed logins, root shells, and recent login history.",
    ),
    (
        "erislite/accounts/users.py",
        "users.py",
        "Suspicious user account scan: UID anomalies, shells, and account configuration.",
    ),
    (
        "erislite/accounts/ssh_keys.py",
        "ssh_keys.py",
        "SSH authorized_keys enumeration across user home directories.",
    ),
    (
        "erislite/accounts/ssh_config.py",
        "ssh_config.py",
        "sshd_config audit against the ErisLITE hardening baseline.",
    ),

    # ---------------------------------------------------------------------
    # Configuration
    # ---------------------------------------------------------------------
    (
        "erislite/config/settings.py",
        "settings.py",
        "Application-wide settings, runtime defaults, and path definitions.",
    ),
    (
        "erislite/config/theme.py",
        "theme.py",
        "Shared ErisLITE terminal theme and presentation constants.",
    ),
    (
        "erislite/config/logging.py",
        "logging.py",
        "Shared ErisLITE runtime logging configuration.",
    ),

    # ---------------------------------------------------------------------
    # Containers
    # ---------------------------------------------------------------------
    (
        "erislite/containers/docker.py",
        "docker.py",
        "Docker security check: privileged containers and risky host exposure.",
    ),

    # ---------------------------------------------------------------------
    # Network
    # ---------------------------------------------------------------------
    (
        "erislite/network/scan.py",
        "scan.py",
        "Network listener scan and structured network discovery.",
    ),
    (
        "erislite/network/tools.py",
        "tools.py",
        "Network utilities: addressing, DNS, diagnostics, WHOIS, and connections.",
    ),
    (
        "erislite/network/ports.py",
        "ports.py",
        "TCP port scanner with service identification and reporting.",
    ),
    (
        "erislite/network/listeners.py",
        "listeners.py",
        "Heuristic network listener inspection and suspicious bind detection.",
    ),
    (
        "erislite/network/firewall.py",
        "firewall.py",
        "Firewall status inspection for UFW, firewalld, nftables, and iptables.",
    ),
    (
        "erislite/network/hosts.py",
        "hosts.py",
        "/etc/hosts inspection for suspicious redirects and tampering.",
    ),

    # ---------------------------------------------------------------------
    # Persistence
    # ---------------------------------------------------------------------
    (
        "erislite/persistence/cron.py",
        "cron.py",
        "Cron job and systemd timer inspection for suspicious scheduled tasks.",
    ),
    (
        "erislite/persistence/suid.py",
        "suid.py",
        "SUID/SGID binary scan for unexpected privileged executables.",
    ),
    (
        "erislite/persistence/backdoors.py",
        "backdoors.py",
        "Shell init, profile, and LD_PRELOAD persistence inspection.",
    ),
    (
        "erislite/persistence/world_writable.py",
        "world_writable.py",
        "World-writable file and directory inspection in critical filesystem paths.",
    ),

    # ---------------------------------------------------------------------
    # Response
    # ---------------------------------------------------------------------
    (
        "erislite/response/security_log.py",
        "security_log.py",
        "Security audit log writer for structured ErisLITE findings.",
    ),
    (
        "erislite/response/rapid_response/menu.py",
        "menu.py",
        "Rapid Response menu and workflow entry point.",
    ),
    (
        "erislite/response/rapid_response/triage.py",
        "triage.py",
        "Rapid Response triage and host assessment routines.",
    ),
    (
        "erislite/response/rapid_response/actions.py",
        "actions.py",
        "Rapid Response containment and remediation actions.",
    ),
    (
        "erislite/response/rapid_response/undo.py",
        "undo.py",
        "Rapid Response rollback and undo operations.",
    ),
    (
        "erislite/response/rapid_response/utils.py",
        "utils.py",
        "Shared Rapid Response utility functions and runtime paths.",
    ),

    # ---------------------------------------------------------------------
    # Sweep
    # ---------------------------------------------------------------------
    (
        "erislite/sweep/snapshot.py",
        "snapshot.py",
        "Captures a system snapshot to a timestamped ErisLITE log.",
    ),
    (
        "erislite/sweep/threat_sweep.py",
        "threat_sweep.py",
        "Threat sweep orchestrator: runs selected modules, scores risk, and saves results.",
    ),
    (
        "erislite/sweep/viewer.py",
        "viewer.py",
        "Threat sweep log viewer for browsing and inspecting saved sweep results.",
    ),
    (
        "erislite/sweep/log_viewer.py",
        "log_viewer.py",
        "Snapshot log viewer for browsing and displaying saved snapshot logs.",
    ),
    (
        "erislite/sweep/soc_mode.py",
        "soc_mode.py",
        "SOC Mode rolling snapshot and posture assessment.",
    ),

    # ---------------------------------------------------------------------
    # System
    # ---------------------------------------------------------------------
    (
        "erislite/system/info.py",
        "info.py",
        "System information collection and display.",
    ),
    (
        "erislite/system/processes.py",
        "processes.py",
        "Process anomaly inspection for suspicious paths and execution context.",
    ),
    (
        "erislite/system/kernel_modules.py",
        "kernel_modules.py",
        "Kernel module inspection for known-bad names, untracked modules, and unusual paths.",
    ),
    (
        "erislite/system/integrity.py",
        "integrity.py",
        "SHA-256 file integrity baseline creation and change detection.",
    ),
    (
        "erislite/system/security_audit.py",
        "security_audit.py",
        "Snapshot-style host security posture assessment.",
    ),

    # ---------------------------------------------------------------------
    # Vulnerability
    # ---------------------------------------------------------------------
    (
        "erislite/vulnerability/cve_checker.py",
        "cve_checker.py",
        "Offline CVE version checking for installed software.",
    ),
    (
        "erislite/vulnerability/cve_tools.py",
        "cve_tools.py",
        "Offline CVE search and lookup against the local cache.",
    ),

    # ---------------------------------------------------------------------
    # UI
    # ---------------------------------------------------------------------
    (
        "erislite/ui/cli.py",
        "cli.py",
        "Main ErisLITE CLI menu loop.",
    ),
    (
        "erislite/ui/splash.py",
        "splash.py",
        "Startup splash screen with host profile and version information.",
    ),
    (
        "erislite/ui/utils.py",
        "utils.py",
        "Shared UI utilities for screen control, headers, prompts, and platform detection.",
    ),
    (
        "erislite/ui/console.py",
        "console.py",
        "Shared Rich console instance for ErisLITE terminal output.",
    ),
    (
        "erislite/ui/menus/security_menu.py",
        "security_menu.py",
        "Security tools menu with threat sweep and posture workflows.",
    ),
    (
        "erislite/ui/menus/help_menu.py",
        "help_menu.py",
        "Help and About interface.",
    ),
    (
        "erislite/ui/menus/system_menu.py",
        "system_menu.py",
        "System information menu.",
    ),
    (
        "erislite/ui/menus/network_menu.py",
        "network_menu.py",
        "Network tools menu.",
    ),
    (
        "erislite/ui/menus/cve_tools_menu.py",
        "cve_tools_menu.py",
        "CVE tools launcher menu.",
    ),

    # ---------------------------------------------------------------------
    # Version
    # ---------------------------------------------------------------------
    (
        "erislite/version.py",
        "version.py",
        "Single source of truth for ErisLITE version and build metadata.",
    ),
]


HEADER_PATTERN = re.compile(
    r"\A"
    r"(?:# Project:.*\n)?"
    r"(?:# Module:.*\n)?"
    r"(?:# Author:.*\n)?"
    r"(?:# Version:.*\n)?"
    r"(?:# License:.*\n)?"
    r"(?:# Created:.*\n)?"
    r"(?:# Last Updated:.*\n)?"
    r"(?:# Description:.*\n)?"
)


def make_header(module_name: str, description: str) -> str:
    return (
        "# Project: ErisLITE\n"
        f"# Module: {module_name}\n"
        "# Author: Liam Piper-Brandon\n"
        f"# Version: {VERSION}\n"
        "# License: MIT\n"
        "# Created: 2025-06-01\n"
        f"# Last Updated: {TODAY}\n"
        f"# Description: {description}\n"
    )


def update_file(
    path: Path,
    module_name: str,
    description: str,
) -> bool:
    content = path.read_text(
        encoding="utf-8"
    )

    new_header = make_header(
        module_name,
        description,
    )

    # Preserve shebang if present.
    shebang = ""

    if content.startswith("#!"):
        newline = content.find("\n")

        if newline != -1:
            shebang = content[: newline + 1]
            content = content[newline + 1 :]

    # Preserve __future__ import before normal imports but place
    # the project header ahead of it.
    content = HEADER_PATTERN.sub(
        "",
        content,
        count=1,
    )

    content = content.lstrip("\n")

    updated_content = (
        shebang
        + new_header
        + "\n"
        + content
    )

    path.write_text(
        updated_content,
        encoding="utf-8",
    )

    return True


def main() -> None:
    updated = []
    skipped = []

    for rel_path, module_name, description in FILES:
        path = Path(rel_path)

        if not path.exists():
            skipped.append(rel_path)
            continue

        update_file(
            path,
            module_name,
            description,
        )

        updated.append(rel_path)

    print(
        f"\nUpdated {len(updated)} file(s):"
    )

    for path in updated:
        print(f"  ✓ {path}")

    if skipped:
        print(
            f"\nSkipped {len(skipped)} file(s) "
            "(not found):"
        )

        for path in skipped:
            print(f"  - {path}")


if __name__ == "__main__":
    main()