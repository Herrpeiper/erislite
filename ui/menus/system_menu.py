# Project: ErisLITE
# Module: system_menu.py
# Author: Liam Piper-Brandon
# Version: 1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-04-05
# Description: System info menu.

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from core import system_info

from ui.utils import clear_screen, show_header, pause_return

console = Console()

def run(profile: dict):
    clear_screen()
    show_header("SYSTEM INFO")

    try:
        os_name = system_info.get_os_info()
    except Exception:
        os_name = "Unavailable"

    try:
        kernel = system_info.get_kernel_version()
    except Exception:
        kernel = "Unavailable"

    try:
        uptime = system_info.get_uptime()
    except Exception:
        uptime = "Unavailable"

    try:
        users = system_info.get_logged_in_users()
    except Exception:
        users = "Unavailable"

    table = Table(title="Host Summary", show_header=True, header_style="bold magenta")
    table.add_column("Property", style="cyan", no_wrap=True)
    table.add_column("Value", style="green")

    table.add_row("Operating System", os_name)
    table.add_row("Kernel", kernel)
    table.add_row("Uptime", uptime)
    table.add_row("Logged-in Users", str(users))

    console.print(table)
    pause_return()
