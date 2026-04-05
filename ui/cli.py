# Project: ErisLITE
# Module: cli.py
# Author: Liam Piper-Brandon
# Version: 1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-04-05
# Description: Main CLI menu loop.

import os

from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

from ui.menus import cve_tools_menu, help_menu, network_menu, security_menu, system_menu
from ui.utils import clear_screen, show_header

from tools import snapshot
from core import log_viewer, cve_checker

console = Console()

def get_privilege_label():
    if os.geteuid() == 0:
        return "[red]ROOT ACCESS[/]"
    else:
        return "[green]User Session[/]"

def launch_cli(profile: dict):
    hostname = profile.get("hostname", "unknown-host")
    role = profile.get("role", "unknown-role")
    analyst_id = profile.get("analyst_id", "N/A")

    while True:
        clear_screen()
        show_header(f"ERISLITE MAIN MENU – {hostname.upper()} [{role.upper()}] – Analyst #{analyst_id} – {get_privilege_label()}")

        menu = Table(show_header=False, box=None, padding=(0, 2))
        menu.add_row("[1]", "🖥️  System Info")
        menu.add_row("", "")
        menu.add_row("[2]", "🌐  Network Tools")
        menu.add_row("", "")
        menu.add_row("[3]", "🛡️  Security Tools")
        menu.add_row("", "")
        menu.add_row("[4]", "📸  Snapshot System State")
        menu.add_row("", "")
        menu.add_row("[5]", "📂  View Snapshot Logs")
        menu.add_row("", "")
        menu.add_row("[6]", "📘  CVE Tools")
        menu.add_row("", "")
        menu.add_row("[7]", "💡  Help / About")
        menu.add_row("", "")
        menu.add_row("[8]", "🚪  Exit")

        console.print(menu)

        choice = Prompt.ask(
            "\nSelect an option",
            default="",
            show_default=False
        ).strip()

        if choice == "1":
            system_menu.run(profile)
        elif choice == "2":
            network_menu.run(profile)
        elif choice == "3":
            security_menu.run(profile)
        elif choice == "4":
            snapshot.capture(profile)
        elif choice == "5":
            log_viewer.view_snapshot_logs()
        elif choice == "6":
            cve_tools_menu.launch_cve_tools_menu()
        elif choice == "7":
            help_menu.show_help()
        elif choice == "8":
            console.print("\n[bold yellow]Exiting ErisLite. Stay frosty.[/]\n")
            break
        else:
            console.print("[red]Invalid option.[/]")
