# Project: ErisLITE
# Module: system_menu.py
# Author: Liam Piper-Brandon
# Version: 1.1
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-01
# Description: System information screen.

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from erislite.config.settings import APP_NAME, APP_VERSION
from erislite.system import info
from erislite.ui.console import console
from erislite.ui.utils import clear_screen, pause_return


def run(profile: dict) -> None:
    clear_screen()

    hostname = profile.get("hostname", "unknown-host")
    role = profile.get("role", "unknown-role")
    analyst_id = profile.get("analyst_id", "N/A")

    header = Panel(
        Text.from_markup(
            f"[dim]Host:[/] [white]{hostname}[/]   "
            f"[dim]Role:[/] [white]{role}[/]   "
            f"[dim]Analyst:[/] [white]{analyst_id}[/]"
        ),
        title="[bold cyan]SYSTEM INFO[/]",
        subtitle=f"[dim cyan]{APP_NAME} v{APP_VERSION}[/]",
        border_style="cyan",
        box=box.SQUARE,
        padding=(0, 1),
    )

    console.print(header)
    console.print()

    try:
        os_name = info.get_os_info()
    except Exception:
        os_name = "Unavailable"

    try:
        kernel = info.get_kernel_version()
    except Exception:
        kernel = "Unavailable"

    try:
        uptime = info.get_uptime()
    except Exception:
        uptime = "Unavailable"

    try:
        users = info.get_logged_in_users()
    except Exception:
        users = "Unavailable"

    table = Table(
        title="[italic cyan]Host Summary[/]",
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
        show_edge=False,
        padding=(0, 1),
    )

    table.add_column("Property", style="cyan", no_wrap=True, min_width=18)
    table.add_column("Value", style="white")

    table.add_row("Operating System", os_name)
    table.add_row("Kernel", kernel)
    table.add_row("Uptime", uptime)
    table.add_row("Logged-in Users", str(users))

    console.print(table)
    console.print()

    pause_return()