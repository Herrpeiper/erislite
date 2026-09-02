# Project: ErisLITE
# Module: help_menu.py
# Author: Liam Piper-Brandon
# Version: 1.1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-02
# Description: Help and About interface.

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from erislite.config.settings import APP_DESCRIPTION, APP_NAME, APP_VERSION
from erislite.ui.console import console
from erislite.ui.utils import clear_screen, pause_return


def _header() -> None:
    console.print(
        Panel(
            Text.from_markup("[dim]Toolkit information and usage reference[/]"),
            title="[bold cyan]HELP / ABOUT[/]",
            subtitle=f"[dim cyan]{APP_NAME} v{APP_VERSION}[/]",
            border_style="cyan",
            box=box.SQUARE,
            padding=(0, 1),
        )
    )
    console.print()


def show_help() -> None:
    clear_screen()
    _header()

    console.print(
        Panel.fit(
            f"[bold cyan]{APP_NAME}[/]\n"
            f"[white]{APP_DESCRIPTION}[/]\n\n"
            "[dim]Designed for Linux security triage, competition environments, "
            "and educational auditing.[/]",
            title="[bold cyan]ABOUT[/]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )
    console.print()

    info = Table(
        box=box.SIMPLE_HEAVY,
        show_header=False,
        show_edge=False,
        padding=(0, 1),
    )
    info.add_column("Field", style="cyan", no_wrap=True)
    info.add_column("Value", style="white")

    info.add_row("Version", APP_VERSION)
    info.add_row("Developer", "Liam Piper-Brandon")
    info.add_row("Platform", "Linux")
    info.add_row("Interface", "Interactive CLI")

    console.print(info)
    console.print()

    modules = Table(
        title="[italic cyan]Core Capabilities[/]",
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
        show_edge=False,
        padding=(0, 1),
    )
    modules.add_column("Module", style="cyan", no_wrap=True)
    modules.add_column("Purpose", style="white")

    modules.add_row(
        "System Information",
        "Hardware, operating system, uptime, and host details.",
    )
    modules.add_row(
        "Network Tools",
        "IP addressing, gateway, DNS, diagnostics, connections, and WHOIS.",
    )
    modules.add_row(
        "Security Tools",
        "Host auditing, persistence checks, account analysis, and hardening review.",
    )
    modules.add_row(
        "Threat Sweep",
        "Consolidated security checks with risk scoring and threat insights.",
    )
    modules.add_row(
        "Snapshot",
        "Capture and review system state for later comparison.",
    )
    modules.add_row(
        "CVE Tools",
        "Offline vulnerability and version-based CVE lookup.",
    )
    modules.add_row(
        "Rapid Response",
        "Dry-run and live containment workflow for detected threats.",
    )
    modules.add_row(
        "SOC Mode",
        "Short-window authentication and activity triage.",
    )

    console.print(modules)
    console.print()

    console.print(
        Panel.fit(
            "[dim]Navigation:[/] [white]Use menu numbers to select tools.[/]\n"
            "[dim]Return:[/] [white]Use [0] Back or the return prompt where available.[/]\n"
            "[dim]Logs:[/] [white]Runtime output is stored under data/logs/.[/]\n"
            "[dim]Privilege:[/] [white]Some checks require root access for full visibility.[/]",
            title="[bold cyan]USAGE[/]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )

    pause_return()
