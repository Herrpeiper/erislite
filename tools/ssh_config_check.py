# Project: ErisLITE
# Module: ssh_config_check.py
# Author: Liam Piper-Brandon
# Version: 1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-04-05
# Description: sshd_config audit against secure defaults.

import os

from rich.console import Console
from rich.table import Table
from rich.align import Align

from ui.utils import clear_screen, show_header, pause_return

console = Console()

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
            "tags": ["ssh_config_unreadable"]
        }

    issues = []
    flagged = False

    if not silent:
        clear_screen()
        show_header("SSH CONFIGURATION CHECK")

        table = Table(title="sshd_config Security Audit", show_lines=True)
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="magenta")
        table.add_column("Status", style="yellow")

        for key, expected in SECURE_DEFAULTS.items():
            actual = config.get(key, "[not set]")
            if actual == "[not set]":
                status = "[yellow]Not Explicitly Set[/]"
            elif actual != expected:
                status = "[red]Insecure[/]"
                flagged = True
                issues.append(f"{key} is '{actual}' (recommended: '{expected}')")
            else:
                status = "[green]Secure[/]"

            table.add_row(key, actual, status)

        console.print(Align.center(table))
        pause_return()

    if flagged:
        return {
            "status": "warning",
            "details": issues,
            "tags": ["weak_ssh_config"]
        }
    else:
        return {
            "status": "ok",
            "details": ["No insecure SSH configuration options detected."],
            "tags": []
        }
