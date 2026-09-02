# Project: ErisLITE
# Module: login_audit.py
# Author: Liam Piper-Brandon
# Version: 1.1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-02
# Description: Login and authentication audit: failed logins, root shells, and recent login history.

import re
import subprocess

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from erislite.config.settings import APP_NAME, APP_VERSION
from erislite.ui.console import console
from erislite.ui.utils import clear_screen, get_os, pause_return

FAILED_LOGIN_THRESHOLD = 3

ROOT_SHELLS = {
    "/bin/bash",
    "/bin/sh",
    "/bin/dash",
    "/bin/zsh",
    "/usr/bin/bash",
    "/usr/bin/sh",
    "/usr/bin/zsh",
}


def _header() -> None:
    console.print(
        Panel(
            Text.from_markup(
                "[dim]Review authentication failures, recent logins, and privileged shells[/]"
            ),
            title="[bold cyan]LOGIN / AUTH AUDIT[/]",
            subtitle=f"[dim cyan]{APP_NAME} v{APP_VERSION}[/]",
            border_style="cyan",
            box=box.SQUARE,
            padding=(0, 1),
        )
    )
    console.print()


def get_failed_logins() -> list[str]:
    output = ""

    try:
        result = subprocess.run(
            ["journalctl", "-u", "ssh", "-n", "100"],
            capture_output=True,
            text=True,
        )

        if result.returncode == 0:
            output = result.stdout

    except Exception:
        pass

    if not output:
        try:
            with open(
                "/var/log/auth.log",
                "r",
                encoding="utf-8",
                errors="ignore",
            ) as file:
                output = file.read()
        except Exception:
            return []

    return re.findall(
        r"Failed password for.*? from .*? port \d+",
        output,
    )


def get_recent_logins() -> list[str]:
    try:
        result = subprocess.run(
            ["last", "-n", "10"],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            return []

        return [
            line
            for line in result.stdout.strip().splitlines()
            if line and not line.startswith("wtmp begins")
        ]

    except Exception:
        return []


def get_uid0_shells() -> list[str]:
    try:
        result = subprocess.run(
            ["ps", "-eo", "uid=,pid=,tty=,comm=,args="],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            return []

        shells = []

        for line in result.stdout.splitlines():
            parts = line.split(None, 4)

            if len(parts) < 5:
                continue

            uid, pid, tty, comm, args = parts

            if uid != "0":
                continue

            # No terminal attached = service/wrapper/background process,
            # not an interactive root shell session.
            if tty in ("?", "-"):
                continue

            command = args.split()[0] if args else ""

            if command in ROOT_SHELLS:
                shells.append(
                    f"PID {pid} — {tty} — {comm} — {args}"
                )

        return shells

    except Exception:
        return []

def run_login_audit(silent: bool = False) -> dict:
    if get_os() != "Linux":
        if not silent:
            clear_screen()
            _header()

            console.print(
                Panel.fit(
                    "[yellow]Login / Auth Audit is only supported on Linux.[/]",
                    border_style="yellow",
                    box=box.ROUNDED,
                )
            )

            pause_return()

        return {
            "status": "unsupported",
            "details": [],
            "tags": [],
        }

    results = {
        "failed_logins": get_failed_logins(),
        "recent_logins": get_recent_logins(),
        "uid0_shells": get_uid0_shells(),
        "flagged": False,
        "issues": [],
        "status": "ok",
        "details": [],
        "tags": [],
    }

    if len(results["failed_logins"]) > FAILED_LOGIN_THRESHOLD:
        results["flagged"] = True
        results["issues"].append(
            f"{len(results['failed_logins'])} failed login attempts detected"
        )
        results["tags"].append("auth_failures")

    if results["uid0_shells"]:
        results["flagged"] = True
        results["issues"].append(
            f"{len(results['uid0_shells'])} root shell session(s) detected"
        )
        results["tags"].append("uid0_shells")

    if results["flagged"]:
        results["status"] = "warning"
        results["details"] = results["issues"]
    else:
        results["details"] = ["No login anomalies detected."]

    if silent:
        return results

    clear_screen()
    _header()

    console.print(
        Panel.fit(
            f"[dim]Recent Logins:[/] [white]{len(results['recent_logins'])}[/]   "
            f"[dim]Failed Attempts:[/] "
            f"[{'yellow' if results['failed_logins'] else 'green'}]"
            f"{len(results['failed_logins'])}[/]   "
            f"[dim]Root Shells:[/] "
            f"[{'yellow' if results['uid0_shells'] else 'green'}]"
            f"{len(results['uid0_shells'])}[/]",
            title="[bold cyan]SUMMARY[/]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )
    console.print()

    if results["recent_logins"]:
        table = Table(
            title="[italic cyan]Recent Logins[/]",
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
            show_edge=False,
            padding=(0, 1),
        )
        table.add_column("Entry", style="white")

        for line in results["recent_logins"]:
            table.add_row(line)

        console.print(table)
        console.print()

    else:
        console.print(
            "[dim]No recent login entries found.[/]"
        )
        console.print()

    if results["failed_logins"]:
        table = Table(
            title=f"[italic cyan]Failed Logins ({len(results['failed_logins'])})[/]",
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
            show_edge=False,
            padding=(0, 1),
        )
        table.add_column("Attempt", style="white")

        for entry in results["failed_logins"][:10]:
            table.add_row(entry)

        console.print(table)
        console.print()

    if results["uid0_shells"]:
        table = Table(
            title=f"[italic cyan]Root Shell Sessions ({len(results['uid0_shells'])})[/]",
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
            show_edge=False,
            padding=(0, 1),
        )
        table.add_column("Session", style="white")

        for entry in results["uid0_shells"]:
            table.add_row(entry)

        console.print(table)
        console.print()

    if results["flagged"]:
        console.print(
            Panel.fit(
                "\n".join(
                    f"[yellow]{issue}[/]"
                    for issue in results["issues"]
                )
                + "\n[dim]Review authentication activity and validate privileged sessions.[/]",
                title="[bold yellow]REVIEW REQUIRED[/]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )
    else:
        console.print(
            Panel.fit(
                "[green]No login anomalies detected.[/]\n"
                "[dim]Authentication activity is within the current heuristic thresholds.[/]",
                title="[bold green]STATUS: OK[/]",
                border_style="green",
                box=box.ROUNDED,
            )
        )

    pause_return()
    return results