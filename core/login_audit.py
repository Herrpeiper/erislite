# Project: ErisLITE
# Module: login_audit.py
# Author: Liam Piper-Brandon
# Version: 0.7
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-03-29
# Description: Login and auth audit: failed logins, root shells, recent login history.

import subprocess, re

from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.align import Align

from ui.utils import clear_screen, show_header, pause_return, get_os

console = Console()

# Get failed login attempts from auth logs or journalctl
def get_failed_logins():
    try:
        output = subprocess.check_output(["journalctl", "-u", "ssh", "-n", "100"], text=True)
    except Exception:
        try:
            with open("/var/log/auth.log", "r") as f:
                output = f.read()
        except:
            return []
    return re.findall(r"Failed password for.*? from .*? port \d+", output)

# Get recent login history using the "last" command
def get_recent_logins():
    try:
        output = subprocess.check_output(["last", "-n", "10"], text=True)
        return output.strip().split("\n")
    except:
        return []

# Get any shell sessions running as UID 0 (root)
def get_uid0_shells():
    try:
        output = subprocess.check_output(["ps", "-eo", "uid,cmd"], text=True)
        return [line for line in output.splitlines() if line.startswith("0 ") and "/bin/" in line]
    except:
        return []

# Main function to run the login/auth audit
def run_login_audit(silent=False):
    os_type = get_os()

    if os_type != "Linux":
        if not silent:
            clear_screen()
            show_header("LOGIN/AUTH LOG CHECK")
            console.print("[yellow]This module is only supported on Linux.[/]")
            pause_return()
        return {
            "status": "unsupported",
            "details": [],
            "tags": []
        }

    results = {
        "failed_logins": [],
        "recent_logins": [],
        "uid0_shells": [],
        "flagged": False,
        "issues": [],
        "status": "ok",
        "details": [],
        "tags": []
    }

    # Run checks
    results["failed_logins"] = get_failed_logins()
    if len(results["failed_logins"]) > 3:
        results["flagged"] = True
        results["issues"].append("Multiple failed login attempts")
        results["tags"].append("auth_failures")

    results["recent_logins"] = get_recent_logins()
    results["uid0_shells"] = get_uid0_shells()
    if results["uid0_shells"]:
        results["flagged"] = True
        results["issues"].append("Shell session running as root (UID 0)")
        results["tags"].append("uid0_shells")

    if results["flagged"]:
        results["status"] = "warning"
        results["details"] = results["issues"]
    else:
        results["details"] = ["No login anomalies detected."]

    # Interactive display (Rich)
    if not silent:
        clear_screen()
        show_header("LOGIN/AUTH LOG CHECK")

        console.print("[bold yellow]🔐 Running Login/Auth Audit...[/bold yellow]\n")

        # Show login history
        if results["recent_logins"]:
            table = Table(title="Recent Logins", show_lines=True)
            table.add_column("Entry")
            for line in results["recent_logins"]:
                table.add_row(line)
            console.print(table)
        else:
            console.print("[grey62]No recent login entries found.[/grey62]")

        # Show failed logins
        if results["failed_logins"]:
            console.print(f"\n[red]⚠ {len(results['failed_logins'])} failed login(s) detected:[/red]")
            for f in results["failed_logins"][:5]:
                console.print(f"  • {f}")
        else:
            console.print("\n[green]No failed login attempts found.[/green]")

        # Show UID 0 shells
        if results["uid0_shells"]:
            console.print(f"\n[red]⚠ {len(results['uid0_shells'])} root shell(s) detected:[/red]")
            for proc in results["uid0_shells"]:
                console.print(f"  • {proc}")
        else:
            console.print("\n[green]No root shell sessions found.[/green]")

        pause_return()

    return results