# Project: ErisLITE
# Module: user_anomaly.py
# Author: Liam Piper-Brandon
# Version: 0.7
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-03-29
# Description: Suspicious user account scan: UID 0 clones, bad shells, hidden accounts.

import pwd, os, json

from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.align import Align

from ui.utils import clear_screen, show_header, pause_return, get_os

console = Console()

# Shells that should NOT appear for service/system users
INTERACTIVE_SHELLS = ["/bin/bash", "/bin/sh", "/usr/bin/zsh", "/usr/bin/fish", "/usr/bin/python", "/usr/bin/perl"]

# Known system/service accounts to ignore unless truly suspicious
KNOWN_SERVICE_USERS = {
    "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news",
    "uucp", "proxy", "www-data", "backup", "list", "irc", "gnats", "nobody",
    "systemd-network", "systemd-resolve", "messagebus", "systemd-timesync",
    "syslog", "systemd-oom", "tcpdump", "avahi-autoipd", "usbmux", "dnsmasq",
    "kernoops", "avahi", "cups-pk-helper", "rtkit", "whoopsie", "sssd",
    "speech-dispatcher", "fwupd-refresh", "nm-openvpn", "saned", "colord",
    "geoclue", "pulse", "gnome-initial-setup", "hplip", "gdm", "clamav", "sshd",
    "_apt", "uuidd", "tss"
}

def run_user_scan(silent=False):
    os_type = get_os()

    if os_type != "Linux":
        if not silent:
            clear_screen()
            show_header("HIDDEN / SUSPICIOUS USER SCAN")
            console.print("[yellow]This module is only supported on Linux.[/]")
            pause_return()
        return {
            "status": "unsupported",
            "details": [],
            "tags": []
        }

    if not silent:
        clear_screen()
        show_header("HIDDEN / SUSPICIOUS USER SCAN")

    flagged = []

    try:
        for user in pwd.getpwall():
            username = user.pw_name
            uid = user.pw_uid
            gid = user.pw_gid
            home = user.pw_dir
            shell = user.pw_shell

            if username in KNOWN_SERVICE_USERS:
                continue

            if uid == 0 and username != "root":
                flagged.append((username, "UID 0 (root clone)"))

            if uid < 1000 and shell in INTERACTIVE_SHELLS and username != "root":
                flagged.append((username, f"Shell access on system UID {uid}"))

            if not home or home in ["/", "/dev/null"]:
                flagged.append((username, "No valid home directory"))

            if shell in ["/usr/bin/python", "/usr/bin/perl", "/dev/null"]:
                flagged.append((username, f"Suspicious shell: {shell}"))

            try:
                if shell and shell not in open("/etc/shells").read():
                    flagged.append((username, f"Non-standard shell: {shell}"))
            except Exception:
                pass

    except Exception as e:
        flagged.append(("Error", str(e)))

    # 🔇 Silent mode
    if silent:
        tags = set()
        for _, reason in flagged:
            if "UID 0" in reason:
                tags.add("uid0_clone")
            elif "Shell access" in reason:
                tags.add("low_uid_shell")
            elif "No valid home" in reason:
                tags.add("no_home_dir")
            elif "Suspicious shell" in reason:
                tags.add("code_shell")
            elif "Non-standard shell" in reason:
                tags.add("nonstandard_shell")

        if tags:
            tags.add("suspicious_login")

        return {
            "status": "ok" if not flagged else "warning",
            "details": [f"{len(flagged)} suspicious account(s) flagged"] if flagged else [],
            "tags": sorted(list(tags)) if tags else []
        }

    # 🖥️ Interactive mode
    if not flagged:
        console.print("[green]No suspicious or hidden users detected.[/]")
        pause_return()
        return {
            "status": "ok",
            "details": [],
            "tags": []
        }

    table = Table(title="Suspicious Users Found", show_lines=True)
    table.add_column("Username")
    table.add_column("Reason")
    for user, reason in flagged:
        table.add_row(user, reason)

    console.print(Align.center(table))
    pause_return()

    return {
        "status": "warning",
        "details": [f"{len(flagged)} suspicious account(s) flagged"],
        "tags": ["suspicious_login"]
    }

