# Project: ErisLITE
# Module: splash.py
# Author: Liam Piper-Brandon
# Version: 1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-04-05
# Description: Startup splash screen with system profile and version info.

import os
import platform
import subprocess
import time
from datetime import datetime
from random import choice

from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from rich import box

from ui.utils import clear_screen
from core.version import VERSION, BUILD_DATE

console = Console()

logo = r"""[cyan]
  ______ _____  _____  _____    _____ _    _ _____ ______ _      _____  
 |  ____|  __ \|_   _|/ ____|  / ____| |  | |_   _|  ____| |    |  __ \ 
 | |__  | |__) | | | | (___   | (___ | |__| | | | | |__  | |    | |  | |
 |  __| |  _  /  | |  \___ \   \___ \|  __  | | | |  __| | |    | |  | |
 | |____| | \ \ _| |_ ____) |  ____) | |  | |_| |_| |____| |____| |__| |
 |______|_|  \_\_____|_____/  |_____/|_|  |_|_____|______|______|_____/ 
[/]"""

quotes = [
    "'You don't win by playing fair.' — Eris Doctrine",
    "'Amateurs hack systems. Professionals hack people.' — Bruce Schneier",
    "'Security is not a product, but a process.' — Bruce Schneier",
    "'There's no patch for human stupidity.' — Kevin Mitnick",
    "'In war, the first casualty is truth.' — Aeschylus"
]

def get_kernel_version():
    return platform.release()

def get_uptime():
    try:
        uptime_seconds = float(open("/proc/uptime").read().split()[0])
        hours = int(uptime_seconds // 3600)
        minutes = int((uptime_seconds % 3600) // 60)
        return f"{hours}h {minutes}m"
    except:
        return "Unknown"

def show_splash(profile: dict):
    hostname = profile.get("hostname", "unknown-host")
    role = profile.get("role", "unknown-role")
    segment = profile.get("segment", "unknown-segment")
    analyst_id = profile.get("analyst_id", "N/A")
    edge_fw = profile.get("edge_firewall", "N/A")

    # Version string pulled from core.version — no hardcoded strings here
    version_tag = f"[bold blue]ErisLite v{VERSION} - Beta Release[/] [dim]| Build: {BUILD_DATE}[/dim]"

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    kernel = get_kernel_version()
    uptime = get_uptime()
    quote = choice(quotes)

    info_panel = Panel.fit(
        f"[bold white]Hostname:[/] {hostname}\n"
        f"[bold white]Role:[/] {role}  |  [bold white]Segment:[/] {segment}\n"
        f"[bold white]Analyst ID:[/] {analyst_id}  |  [bold white]Firewall:[/] {edge_fw}\n"
        f"[bold white]Kernel:[/] {kernel}  |  [bold white]Uptime:[/] {uptime}",
        title="[green]System Profile",
        border_style="blue",
        box=box.ROUNDED,
        padding=(1, 2)
    )

    clear_screen()
    console.print(Align.center(logo))
    console.print(Align.center(version_tag))
    console.print(Align.center(info_panel))
    console.print(f"\n[dim]Session started at {now}[/dim]", justify="center")
    console.print(Align.center("[bold cyan]════════════════════════════════════════════[/]"))
    console.print(Align.center(f"[italic white]{quote}[/]"))
    console.print(Align.center("[bold cyan]════════════════════════════════════════════[/]"))
    time.sleep(1.5)
