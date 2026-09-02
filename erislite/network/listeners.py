# Project: ErisLITE
# Module: listeners.py
# Author: Liam Piper-Brandon
# Version: 1.1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-02
# Description: Heuristic network listener inspection and suspicious bind detection.

import re, subprocess

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from erislite.config.settings import APP_NAME, APP_VERSION
from erislite.ui.console import console
from erislite.ui.utils import clear_screen, get_os, pause_return

WHITELISTED_PROCS = {
    "sshd",
    "cupsd",
    "avahi-daemon",
    "NetworkManager",
    "systemd-resolved",
}

SUSPICIOUS_PROC_NAMES = {"nc", "ncat", "socat"}
UNCOMMON_PORT_THRESHOLD = 1024


def _header() -> None:
    console.print(
        Panel(
            Text.from_markup(
                "[dim]Review listening services, exposure, and suspicious binds[/]"
            ),
            title="[bold cyan]LISTENER CHECK[/]",
            subtitle=f"[dim cyan]{APP_NAME} v{APP_VERSION}[/]",
            border_style="cyan",
            box=box.SQUARE,
            padding=(0, 1),
        )
    )
    console.print()


def extract_process_name(pid_info: str) -> str:
    match = re.search(r'users:\(\("([^"]+)"', pid_info)
    return match.group(1) if match else "unknown"


def _parse_port(local_address: str) -> int:
    if ":" not in local_address:
        return 0

    try:
        return int(local_address.rsplit(":", 1)[-1])
    except ValueError:
        return 0


def _is_loopback(local_address: str) -> bool:
    return (
        local_address.startswith("127.")
        or local_address.startswith("[::1]")
        or local_address.startswith("::1")
    )


def _is_external_bind(local_address: str) -> bool:
    return (
        "0.0.0.0" in local_address
        or "[::]" in local_address
        or local_address.startswith("::")
    )


def parse_listeners():
    """
    Return:
        (proto, local_address, proc_name, flags, is_whitelisted)
    """
    try:
        result = subprocess.run(
            ["ss", "-tulnp"],
            capture_output=True,
            text=True,
        )

        flagged = []

        for line in result.stdout.splitlines()[1:]:
            parts = line.split()

            if len(parts) < 5:
                continue

            proto = parts[0].lower()
            local_address = parts[4]
            pid_info = parts[-1] if parts[-1].startswith("users:") else ""
            proc_name = extract_process_name(pid_info).strip()

            port = _parse_port(local_address)
            is_whitelisted = proc_name in WHITELISTED_PROCS
            flags = []

            if _is_external_bind(local_address):
                flags.append("External Bind")

            if port > UNCOMMON_PORT_THRESHOLD:
                flags.append("High Port")

            if proc_name.lower() in SUSPICIOUS_PROC_NAMES:
                flags.append("Potential LOLBin Listener")

            if is_whitelisted:
                flags.append("Known Service")

            if _is_loopback(local_address):
                flags.append("Loopback")

            notable = [flag for flag in flags if flag != "Known Service"]

            if notable:
                flagged.append(
                    (
                        proto,
                        local_address,
                        proc_name,
                        flags,
                        is_whitelisted,
                    )
                )

        return flagged

    except Exception as e:
        return [
            (
                "error",
                "-",
                str(e),
                ["Error"],
                False,
            )
        ]


def _is_suspicious(flags, is_whitelisted: bool) -> bool:
    has_lolbin = any("LOLBin" in flag for flag in flags)
    has_external = "External Bind" in flags

    return has_lolbin or (not is_whitelisted and has_external)


def _severity(flags, is_whitelisted: bool) -> str:
    return (
        "[yellow]WARNING[/]"
        if _is_suspicious(flags, is_whitelisted)
        else "[green]INFO[/]"
    )


def run_listener_scan(silent: bool = False):
    if get_os() != "Linux":
        if not silent:
            clear_screen()
            _header()

            console.print(
                Panel.fit(
                    "[yellow]Listener Check is only supported on Linux.[/]",
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

    flagged = parse_listeners()

    suspicious = sum(
        1
        for _, _, _, flags, is_whitelisted in flagged
        if _is_suspicious(flags, is_whitelisted)
    )

    if silent:
        if not flagged:
            return {
                "status": "ok",
                "details": [],
                "tags": [],
            }

        if suspicious == 0:
            return {
                "status": "ok",
                "details": [f"{len(flagged)} listener(s) detected (expected/exposure)"],
                "tags": ["listener_exposure"],
            }

        return {
            "status": "warning",
            "details": [
                f"{suspicious} suspicious listener(s) detected "
                f"({len(flagged)} total notable)"
            ],
            "tags": ["suspicious_listener"],
        }

    clear_screen()
    _header()

    if not flagged:
        console.print(
            Panel.fit(
                "[green]No notable listeners detected.[/]\n"
                "[dim]No exposed or suspicious listener conditions were found.[/]",
                title="[bold green]STATUS: OK[/]",
                border_style="green",
                box=box.ROUNDED,
            )
        )

        pause_return()

        return {
            "status": "ok",
            "details": [],
            "tags": [],
        }

    console.print(
        Panel.fit(
            f"[dim]Notable:[/] [white]{len(flagged)}[/]   "
            f"[dim]Suspicious:[/] "
            f"[{'yellow' if suspicious else 'green'}]{suspicious}[/]",
            title="[bold cyan]SUMMARY[/]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )
    console.print()

    table = Table(
        title="[italic cyan]Listener Exposure[/]",
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
        show_edge=False,
        padding=(0, 1),
    )

    table.add_column("Proto", style="cyan", no_wrap=True)
    table.add_column("Local Address", style="white", no_wrap=True)
    table.add_column("Process", style="white", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Flags", style="dim")

    for proto, addr, proc, flags, is_whitelisted in flagged:
        table.add_row(
            proto.upper(),
            addr,
            proc,
            _severity(flags, is_whitelisted),
            ", ".join(flags),
        )

    console.print(table)

    if suspicious:
        console.print()
        console.print(
            Panel.fit(
                f"[yellow]{suspicious} listener(s) require review.[/]\n"
                "[dim]Unknown externally bound services, high-port listeners, "
                "and listener-capable utilities may warrant investigation.[/]",
                title="[bold yellow]REVIEW REQUIRED[/]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )

    pause_return()

    if suspicious == 0:
        return {
            "status": "ok",
            "details": [f"{len(flagged)} listener(s) detected (expected/exposure)"],
            "tags": ["listener_exposure"],
        }

    return {
        "status": "warning",
        "details": [
            f"{suspicious} suspicious listener(s) detected "
            f"({len(flagged)} total notable)"
        ],
        "tags": ["suspicious_listener"],
    }
