# Project: ErisLITE
# Module: cli.py
# Author: Liam Piper-Brandon
# Version: 1.1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-02
# Description: Main ErisLITE CLI menu loop.

import os

from rich import box
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from erislite.config.settings import APP_NAME, APP_VERSION
from erislite.sweep import log_viewer, snapshot
from erislite.ui.console import console
from erislite.ui.menus import (
    cve_tools_menu,
    help_menu,
    network_menu,
    security_menu,
    system_menu,
)
from erislite.ui.utils import clear_screen


def get_privilege_label() -> str:
    return "[bold red]ROOT ACCESS[/]" if os.geteuid() == 0 else "[green]User Session[/]"


def build_menu() -> Table:
    menu = Table(show_header=False, box=None, padding=(0, 1), collapse_padding=True)
    menu.add_column(no_wrap=True)
    menu.add_column()

    menu.add_row("[bold cyan]SYSTEM[/]", "")
    menu.add_row("[cyan][1][/]", "System Information")
    menu.add_row("[cyan][2][/]", "Network Tools")

    menu.add_row("", "")
    menu.add_row("[bold cyan]SECURITY[/]", "")
    menu.add_row("[cyan][3][/]", "Security Tools")
    menu.add_row("[cyan][4][/]", "Snapshot System State")
    menu.add_row("[cyan][5][/]", "View Snapshot Logs")
    menu.add_row("[cyan][6][/]", "CVE Tools")

    menu.add_row("", "")
    menu.add_row("[bold cyan]SUPPORT[/]", "")
    menu.add_row("[cyan][7][/]", "Help / About")
    menu.add_row("[cyan][8][/]", "Exit")

    return menu


def launch_cli(profile: dict) -> None:
    hostname = profile.get("hostname", "unknown-host")
    role = profile.get("role", "unknown-role")
    analyst_id = profile.get("analyst_id", "N/A")

    while True:
        clear_screen()

        metadata = Text.from_markup(
            f"[dim]Host:[/] [white]{hostname}[/]   "
            f"[dim]Role:[/] [white]{role}[/]   "
            f"[dim]Analyst:[/] [white]{analyst_id}[/]   "
            f"[dim]Session:[/] {get_privilege_label()}"
        )

        header = Panel(
            metadata,
            title=f"[bold cyan]{APP_NAME.upper()} MAIN MENU[/]",
            subtitle=f"[dim cyan]{APP_NAME} v{APP_VERSION}[/]",
            border_style="cyan",
            box=box.SQUARE,
            padding=(0, 1),
        )

        console.print(header)
        console.print()
        console.print(build_menu())

        choice = Prompt.ask(
            "\n[cyan]Select an option[/]",
            default="",
            show_default=False,
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
            console.print(f"\n[bold yellow]Exiting {APP_NAME}. Stay frosty.[/]\n")
            break
        else:
            console.print("[red]Invalid option.[/]")
