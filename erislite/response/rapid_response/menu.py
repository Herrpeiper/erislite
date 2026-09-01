# Project: ErisLITE
# Module: menu.py
# Author: Liam Piper-Brandon
# Version: 1.1
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-01
# Description: Rapid Response interactive workflow and presentation layer.

from __future__ import annotations

import json, os
from typing import Dict, List

from rich import box
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from erislite.config.settings import APP_NAME, APP_VERSION
from erislite.response.rapid_response.actions import build_action_plan, execute_action
from erislite.response.rapid_response.triage import (
    flagged_users,
    suspicious_connections,
    suspicious_processes,
    writable_crons,
)
from erislite.response.rapid_response.undo import select_and_undo
from erislite.response.rapid_response.utils import log_path, now
from erislite.ui.console import console
from erislite.ui.utils import clear_screen, get_os, pause_return


def _header(title: str, subtitle: str = "") -> None:
    console.print(
        Panel(
            Text.from_markup(
                subtitle or "[dim]Containment and response operations[/]"
            ),
            title=f"[bold cyan]{title}[/]",
            subtitle=f"[dim cyan]{APP_NAME} v{APP_VERSION}[/]",
            border_style="cyan",
            box=box.SQUARE,
            padding=(0, 1),
        )
    )
    console.print()


def _show_processes(procs) -> None:
    if not procs:
        return

    table = Table(
        title=f"[italic cyan]Suspicious Processes ({len(procs)})[/]",
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
        show_edge=False,
        padding=(0, 1),
    )
    table.add_column("PID", style="cyan", no_wrap=True)
    table.add_column("Name", style="white", no_wrap=True)
    table.add_column("Path", style="white")

    for proc in procs:
        table.add_row(str(proc["pid"]), proc["name"], proc["exe"])

    console.print(table)
    console.print()


def _show_connections(conns) -> None:
    if not conns:
        return

    table = Table(
        title=f"[italic cyan]Suspicious Connections ({len(conns)})[/]",
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
        show_edge=False,
        padding=(0, 1),
    )
    table.add_column("Local", style="white")
    table.add_column("Remote", style="red")
    table.add_column("Process", style="cyan")

    for conn in conns:
        table.add_row(
            conn["laddr"],
            conn["raddr"],
            conn.get("proc", "unknown"),
        )

    console.print(table)
    console.print()


def _show_actions(actions) -> None:
    table = Table(
        title=f"[italic cyan]Proposed Actions ({len(actions)})[/]",
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
        show_edge=False,
        padding=(0, 1),
    )
    table.add_column("#", style="cyan", justify="right")
    table.add_column("Action", style="white")
    table.add_column("Recovery", no_wrap=True)

    for index, action in enumerate(actions, start=1):
        recovery = (
            "[green]Reversible[/]"
            if action["undo"]
            else "[yellow]Irreversible[/]"
        )
        table.add_row(str(index), action["label"], recovery)

    console.print(table)
    console.print()


def run_rapid_response(dry_run: bool = False) -> None:
    if get_os() != "Linux":
        console.print("[yellow]Rapid Response is only supported on Linux.[/]")
        pause_return()
        return

    if os.geteuid() != 0:
        console.print("[bold red]Rapid Response requires root privileges.[/]")
        console.print("[dim]Run ErisLITE with sudo to use this feature.[/]")
        pause_return()
        return

    clear_screen()
    _header("RAPID RESPONSE", "[dim]Triage and containment workflow[/]")

    if dry_run:
        console.print(
            Panel.fit(
                "[bold yellow]DRY RUN[/]   "
                "[dim]No system changes will be made.[/]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )
    else:
        console.print(
            Panel.fit(
                "[bold red]LIVE MODE[/]   "
                "[white]Containment actions will modify this system.[/]",
                border_style="red",
                box=box.ROUNDED,
            )
        )

    console.print()
    console.print("[dim]Running triage scan...[/]")
    console.print()

    procs = suspicious_processes()
    conns = suspicious_connections()
    users = flagged_users()
    crons = writable_crons()

    total = len(procs) + len(conns) + len(users) + len(crons)

    if total == 0:
        console.print("[green]Triage complete — no immediate threats detected.[/]")
        console.print(
            "[dim]Consider running a full Threat Sweep for deeper analysis.[/]"
        )
        pause_return()
        return

    _show_processes(procs)
    _show_connections(conns)

    if users:
        console.print(
            f"[red]Flagged Accounts:[/] [white]{', '.join(users)}[/]\n"
        )

    if crons:
        console.print("[red]World-Writable Cron Files[/]")
        for path in crons:
            console.print(f"  [yellow]{path}[/]")
        console.print()

    actions = build_action_plan(procs, conns, users, crons)
    _show_actions(actions)

    if dry_run:
        console.print("[yellow]Dry run complete — no changes made.[/]")
        pause_return()
        return

    if not Confirm.ask(
        "[bold red]Execute all actions?[/] "
        "[white]This will modify the system.[/]",
        default=False,
    ):
        console.print("[yellow]Rapid Response cancelled.[/]")
        pause_return()
        return

    console.print()
    console.print("[dim]Executing actions...[/]")
    console.print()

    action_log: List[Dict] = []
    success = 0
    failed = 0

    for action in actions:
        if execute_action(action, action_log):
            success += 1
        else:
            failed += 1

    path = log_path()

    log_data = {
        "timestamp": now(),
        "mode": "live",
        "summary": {
            "success": success,
            "failed": failed,
            "total": len(actions),
        },
        "actions": action_log,
    }

    with open(path, "w", encoding="utf-8") as file:
        json.dump(log_data, file, indent=2)

    console.print()
    console.print(
        f"[bold]Complete.[/] "
        f"[green]{success} succeeded[/], "
        f"[red]{failed} failed[/]."
    )
    console.print(f"[dim]Log saved:[/] [white]{path}[/]")

    if any(action.get("undo") for action in action_log):
        console.print(
            "\n[dim]Reversible actions can be restored from "
            "Rapid Response → Undo Previous Run.[/]"
        )

    pause_return()


def run_rapid_response_menu() -> None:
    while True:
        clear_screen()
        _header("RAPID RESPONSE")

        console.print(
            Panel.fit(
                "[bold red]CAUTION[/]\n"
                "[white]Rapid Response can modify system state.[/]\n"
                "[dim]Run Dry Run first to review proposed actions.[/]",
                border_style="red",
                box=box.ROUNDED,
            )
        )
        console.print()

        menu = Table(
            show_header=False,
            box=None,
            padding=(0, 1),
            collapse_padding=True,
        )
        menu.add_column(no_wrap=True)
        menu.add_column()
        menu.add_column()

        menu.add_row("[bold cyan]ACTIONS[/]", "", "")
        menu.add_row(
            "[cyan][1][/]",
            "Dry Run",
            "[dim]Scan and preview actions[/]",
        )
        menu.add_row(
            "[red][2][/]",
            "[red]Live Run[/]",
            "[dim]Execute containment actions[/]",
        )
        menu.add_row(
            "[yellow][3][/]",
            "Undo Previous Run",
            "[dim]Reverse supported actions[/]",
        )
        menu.add_row("", "", "")
        menu.add_row("[cyan][0][/]", "Back", "")

        console.print(menu)

        choice = Prompt.ask(
            "\n[cyan]Select an option[/]",
            choices=["0", "1", "2", "3"],
            default="1",
        )

        if choice == "1":
            run_rapid_response(dry_run=True)
        elif choice == "2":
            run_rapid_response(dry_run=False)
        elif choice == "3":
            select_and_undo()
        elif choice == "0":
            break