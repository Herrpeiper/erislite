# Project: ErisLITE
# Module: ssh_key_check.py
# Author: Liam Piper-Brandon
# Version: 0.7
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-03-29
# Description: SSH authorized_keys enumeration across all user home directories.

import os, pwd

from rich.console import Console
from rich.table import Table
from rich.align import Align

from ui.utils import clear_screen, show_header, pause_return, get_os

console = Console()

# This module checks for the presence of authorized_keys files in user home directories on Linux systems.
def find_authorized_keys():
    key_entries = []
    for user in pwd.getpwall():
        if user.pw_uid < 1000 and user.pw_name != "root":
            continue  # Skip system users except root

        home_dir = user.pw_dir
        auth_keys_path = os.path.join(home_dir, ".ssh", "authorized_keys")

        if os.path.isfile(auth_keys_path):
            try:
                with open(auth_keys_path, 'r') as f:
                    keys = f.readlines()
                    for key in keys:
                        key = key.strip()
                        if key:
                            key_entries.append({
                                "user": user.pw_name,
                                "path": auth_keys_path,
                                "key": key[:40] + "...",  # Truncate
                                "uid": user.pw_uid
                            })
            except Exception:
                continue
    return key_entries

# Main function to run the SSH key check module
def run_ssh_key_check(silent=False):
    os_type = get_os()

    if os_type != "Linux":
        if not silent:
            clear_screen()
            show_header("SSH KEY ENUMERATION")
            console.print("[yellow]This module is only supported on Linux.[/]")
            pause_return()
        return {
            "status": "unsupported",
            "details": [],
            "tags": []
        }

    entries = find_authorized_keys()
    result = {
        "status": "ok",
        "details": [],
        "tags": [],
        "flagged": False,
        "key_count": len(entries)
    }

    if entries:
        result["status"] = "warning"
        result["flagged"] = True
        result["details"].append(f"{len(entries)} authorized_keys file(s) found")

        usernames = {e['user'] for e in entries}
        result["tags"].append("ssh_keys_suspicious")
        if "root" in usernames:
            result["tags"].append("ssh_keys_user_root")
        if len(usernames) > 1:
            result["tags"].append("ssh_keys_multiple_users")
        if any(e['uid'] < 1000 and e['user'] != "root" for e in entries):
            result["tags"].append("ssh_keys_system_user")

    if not silent:
        clear_screen()
        show_header("SSH KEY ENUMERATION")

        if not entries:
            console.print("[green]No authorized_keys files found.[/]")
        else:
            table = Table(title="Discovered SSH Keys", show_lines=True)
            table.add_column("User")
            table.add_column("Path")
            table.add_column("Key (truncated)")

            for entry in entries:
                table.add_row(entry["user"], entry["path"], entry["key"])

            console.print(Align.center(table))

        pause_return()

    return result