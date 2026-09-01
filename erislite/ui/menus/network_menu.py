# Project: ErisLITE
# Module: network_menu.py
# Author: Liam Piper-Brandon
# Version: 1.1
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-01
# Description: Network tools menu.

from rich import box
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from erislite.config.settings import APP_NAME, APP_VERSION
from erislite.network import tools
from erislite.ui.console import console
from erislite.ui.utils import clear_screen


def build_menu() -> Table:
    table = Table(show_header=False, box=None, padding=(0, 1), collapse_padding=True)
    table.add_column(no_wrap=True)
    table.add_column()

    table.add_row("[bold cyan]ADDRESSING[/]", "")
    table.add_row("[cyan][1][/]", "Show IP Addresses")
    table.add_row("[cyan][2][/]", "Show Default Gateway")
    table.add_row("[cyan][3][/]", "Show DNS Servers")
    table.add_row("[cyan][4][/]", "Show External IP")

    table.add_row("", "")
    table.add_row("[bold cyan]DIAGNOSTICS[/]", "")
    table.add_row("[cyan][5][/]", "Ping Host")
    table.add_row("[cyan][6][/]", "Trace Route")

    table.add_row("", "")
    table.add_row("[bold cyan]CONNECTIONS[/]", "")
    table.add_row("[cyan][7][/]", "Show Active Connections")
    table.add_row("[cyan][8][/]", "WHOIS Lookup")

    table.add_row("", "")
    table.add_row("[cyan][0][/]", "Back")

    return table


def run(profile: dict) -> None:
    hostname = profile.get("hostname", "unknown-host")
    role = profile.get("role", "unknown-role")
    analyst_id = profile.get("analyst_id", "N/A")

    while True:
        clear_screen()

        metadata = Text.from_markup(
            f"[dim]Host:[/] [white]{hostname}[/]   "
            f"[dim]Role:[/] [white]{role}[/]   "
            f"[dim]Analyst:[/] [white]{analyst_id}[/]"
        )

        header = Panel(
            metadata,
            title="[bold cyan]NETWORK TOOLS[/]",
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
            tools.show_ips()
        elif choice == "2":
            tools.show_gateway()
        elif choice == "3":
            tools.show_dns()
        elif choice == "4":
            tools.show_external_ip()
        elif choice == "5":
            tools.ping_host()
        elif choice == "6":
            tools.trace_route()
        elif choice == "7":
            tools.show_active_connections()
        elif choice == "8":
            tools.whois_lookup()
        elif choice == "0":
            break
        else:
            console.print("[red]Invalid option.[/]")