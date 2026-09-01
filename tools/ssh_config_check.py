# Project: ErisLITE
# Module: ssh_config_check.py
# Author: Liam Piper-Brandon
# Version: 1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-04-05
# Description: sshd_config audit against secure defaults.

import os

from rich.table import Table
from rich.align import Align

from erislite.ui.console import console
from erislite.ui.utils import clear_screen, show_header, pause_return

# Settings to audit and what value is considered secure
SECURE_DEFAULTS = {
    "PermitRootLogin": "no",
    "PasswordAuthentication": "no",
    "PermitEmptyPasswords": "no",
    "ChallengeResponseAuthentication": "no",
    "UsePAM": "yes",
    "X11Forwarding": "no",
    "AllowTcpForwarding": "no"
}

# This function reads the sshd_config file and extracts relevant settings for auditing.
def parse_sshd_config(path="/etc/ssh/sshd_config"):
    """Parse sshd_config and return a dict of relevant settings."""
    found = {}
    if not os.path.exists(path):
        return None

    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    key, value = parts[0], parts[1]
                    if key in SECURE_DEFAULTS:
                        found[key] = value.lower()
    except Exception:
        return None

    return found

# This function runs the SSH configuration check and returns a structured result.
def run_ssh_config_check(silent=False):
    config = parse_sshd_config()

    if config is None:
        if not silent:
            clear_screen()
            show_header("SSH CONFIGURATION CHECK")
            console.print("[yellow]Could not read /etc/ssh/sshd_config.[/]")
            pause_return()

        return {
            "status": "error",
            "details": ["Unable to read sshd_config"],
            "tags": ["ssh_config_unreadable"],
        }

    issues = []
    findings = []

    # Always analyze, regardless of silent mode
    for key, expected in SECURE_DEFAULTS.items():
        actual = config.get(key)

        if actual is None:
            findings.append(
                {
                    "setting": key,
                    "value": "[not set]",
                    "status": "unset",
                    "expected": expected,
                }
            )
            continue

        if actual != expected:
            issues.append(
                f"{key} is '{actual}' (recommended: '{expected}')"
            )

            findings.append(
                {
                    "setting": key,
                    "value": actual,
                    "status": "insecure",
                    "expected": expected,
                }
            )
        else:
            findings.append(
                {
                    "setting": key,
                    "value": actual,
                    "status": "secure",
                    "expected": expected,
                }
            )

    result = {
        "status": "warning" if issues else "ok",
        "details": issues if issues else [
            "No insecure SSH configuration options detected."
        ],
        "tags": ["weak_ssh_config"] if issues else [],
        "findings": findings,
    }

    if silent:
        return result

    clear_screen()
    show_header("SSH CONFIGURATION CHECK")

    table = Table(
        title="sshd_config Security Audit",
        show_lines=True,
    )

    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="magenta")
    table.add_column("Expected", style="blue")
    table.add_column("Status")

    for finding in findings:
        status = finding["status"]

        if status == "secure":
            status_text = "[green]Secure[/]"
        elif status == "insecure":
            status_text = "[red]Insecure[/]"
        else:
            status_text = "[yellow]Not Explicitly Set[/]"

        table.add_row(
            finding["setting"],
            finding["value"],
            finding["expected"],
            status_text,
        )

    console.print(Align.center(table))
    pause_return()

    return result