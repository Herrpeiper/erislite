# Project: ErisLITE
# Module: firewall_check.py
# Author: Liam Piper-Brandon
# Version: 0.7
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-03-29
# Description: Firewall status check: UFW, firewalld, nftables, iptables.

import subprocess

from rich.console import Console
from rich.table import Table
from rich.align import Align
from ui.utils import clear_screen, show_header, pause_return

console = Console()

# Firewall Check Tool
def run_firewall_check(silent=False):
    status = "ok"
    detail = "Firewall active"
    tags = []

    fw_type = None
    active = False

    try:
        # Check UFW
        ufw = subprocess.run(["ufw", "status"], capture_output=True, text=True)
        if "Status: active" in ufw.stdout:
            fw_type = "ufw"
            active = True
        elif "inactive" in ufw.stdout:
            fw_type = "ufw"
            status = "warning"
            detail = "UFW is inactive"
            tags.append("firewall_ufw_inactive")
    except Exception:
        pass

    try:
        # Check firewalld
        firewalld = subprocess.run(["systemctl", "is-active", "firewalld"], capture_output=True, text=True)
        if "active" in firewalld.stdout:
            fw_type = "firewalld"
            active = True
        elif "inactive" in firewalld.stdout:
            fw_type = "firewalld"
            status = "warning"
            detail = "firewalld is inactive"
            tags.append("firewall_disabled")
    except Exception:
        pass

    try:
        # Check iptables (or nftables) as fallback
        iptables = subprocess.run(["iptables", "-L"], capture_output=True, text=True)
        if "Chain" in iptables.stdout:
            if not active:
                fw_type = "iptables"
                active = True
        else:
            status = "warning"
            detail = "No iptables rules found"
            tags.append("firewall_ip_empty")
    except Exception:
        status = "warning"
        detail = "Unable to detect any firewall"
        tags.append("firewall_disabled")

    if not active and not tags:
        status = "warning"
        detail = "No active firewall detected"
        tags.append("firewall_disabled")

    if silent:
        return {
            "status": status,
            "details": [detail],
            "tags": tags
        }

    # Interactive output
    clear_screen()
    show_header("FIREWALL STATUS CHECK")

    table = Table(title="Firewall Check Results", show_lines=True)
    table.add_column("Firewall Type", style="cyan")
    table.add_column("Status", style="green" if status == "ok" else "red")

    table.add_row(fw_type or "Unknown", detail)
    console.print(Align.center(table))
    pause_return()

    return {
        "status": status,
        "details": [detail],
        "tags": tags
    }