# Project: ErisLITE
# Module: splash.py
# Author: Liam Piper-Brandon
# Version: 1.1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-02
# Description: Startup splash screen with host profile and version information.

import platform
import time
from datetime import datetime
from random import choice

from rich import box
from rich.align import Align
from rich.panel import Panel
from rich.text import Text

from erislite.config.settings import APP_CODE, APP_NAME, APP_VERSION
from erislite.ui.console import console
from erislite.ui.utils import clear_screen
from erislite.version import BUILD_DATE


LOGO = [
    "███████ ██████  ██ ███████     ██      ██ ███████ ███████",
    "██      ██   ██ ██ ██          ██      ██    ██    ██",
    "█████   ██████  ██ ███████     ██      ██    ██    █████",
    "██      ██   ██ ██      ██     ██      ██    ██    ██",
    "███████ ██   ██ ██ ███████     ███████ ██    ██    ███████",
]


QUOTES = [
    "'You don't win by playing fair.' — Eris Doctrine",
    "'Amateurs hack systems. Professionals hack people.' — Bruce Schneier",
    "'Security is not a product, but a process.' — Bruce Schneier",
    "'There's no patch for human stupidity.' — Kevin Mitnick",
    "'In war, the first casualty is truth.' — Aeschylus",
]


def get_kernel_version() -> str:
    return platform.release()


def get_uptime() -> str:
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as uptime_file:
            uptime_seconds = float(uptime_file.read().split()[0])

        hours = int(uptime_seconds // 3600)
        minutes = int((uptime_seconds % 3600) // 60)

        return f"{hours}h {minutes}m"

    except (OSError, ValueError, IndexError):
        return "Unknown"


def show_splash(profile: dict) -> None:
    hostname = profile.get("hostname", "unknown-host")
    role = profile.get("role", "unknown-role")
    segment = profile.get("segment", "unknown-segment")
    analyst_id = profile.get("analyst_id", "N/A")
    edge_fw = profile.get("edge_firewall", "N/A")

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    kernel = get_kernel_version()
    uptime = get_uptime()
    quote = choice(QUOTES)

    logo_text = Text("\n".join(LOGO), style="bold cyan")

    logo_panel = Panel(
        Align.center(logo_text),
        border_style="cyan",
        box=box.SQUARE,
        padding=(0, 2),
    )

    version_tag = Text.from_markup(
        f"[bold cyan]{APP_NAME}[/] "
        f"[bold white]v{APP_VERSION}[/] "
        f"[dim]•[/] "
        f"[white]{APP_CODE}[/] "
        f"[dim]•[/] "
        f"[dim]Build[/] [white]{BUILD_DATE}[/]"
    )

    info_panel = Panel.fit(
        f"[bold white]Hostname:[/] {hostname}\n"
        f"[bold white]Role:[/] {role}  [dim]|[/]  "
        f"[bold white]Segment:[/] {segment}\n"
        f"[bold white]Analyst ID:[/] {analyst_id}  [dim]|[/]  "
        f"[bold white]Firewall:[/] {edge_fw}\n"
        f"[bold white]Kernel:[/] {kernel}  [dim]|[/]  "
        f"[bold white]Uptime:[/] {uptime}",
        title="[green]System Profile[/]",
        border_style="cyan",
        box=box.ROUNDED,
        padding=(1, 2),
    )

    clear_screen()

    console.print(logo_panel)
    console.print()
    console.print(Align.center(version_tag))
    console.print()
    console.print(Align.center(info_panel))

    console.print(
        f"\n[dim]Session started at[/] [cyan]{now}[/]",
        justify="center",
    )

    console.print(Align.center("[cyan]────────────────────────────────────────────[/]"))

    console.print(Align.center(f"[italic white]{quote}[/]"))

    console.print(Align.center("[cyan]────────────────────────────────────────────[/]"))

    time.sleep(1.5)
