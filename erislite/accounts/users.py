# Project: ErisLITE
# Module: users.py
# Author: Liam Piper-Brandon
# Version: 1.1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-02
# Description: Suspicious user account scan: UID anomalies, shells, and account configuration.

import pwd

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from erislite.config.settings import APP_NAME, APP_VERSION
from erislite.ui.console import console
from erislite.ui.utils import clear_screen, get_os, pause_return

INTERACTIVE_SHELLS = {
    "/bin/bash",
    "/bin/sh",
    "/usr/bin/zsh",
    "/usr/bin/fish",
    "/usr/bin/python",
    "/usr/bin/perl",
}

NONLOGIN_SHELLS = {
    "/usr/sbin/nologin",
    "/sbin/nologin",
    "/bin/false",
}

KNOWN_SERVICE_USERS = {
    "daemon",
    "bin",
    "sys",
    "sync",
    "games",
    "man",
    "lp",
    "mail",
    "news",
    "uucp",
    "proxy",
    "www-data",
    "backup",
    "list",
    "irc",
    "gnats",
    "nobody",
    "systemd-network",
    "systemd-resolve",
    "messagebus",
    "systemd-timesync",
    "syslog",
    "systemd-oom",
    "tcpdump",
    "avahi-autoipd",
    "usbmux",
    "dnsmasq",
    "kernoops",
    "avahi",
    "cups-pk-helper",
    "rtkit",
    "whoopsie",
    "sssd",
    "speech-dispatcher",
    "fwupd-refresh",
    "nm-openvpn",
    "saned",
    "colord",
    "geoclue",
    "pulse",
    "gnome-initial-setup",
    "hplip",
    "gdm",
    "clamav",
    "sshd",
    "_apt",
    "uuidd",
    "tss",
    "polkitd",
}


def _header() -> None:
    console.print(
        Panel(
            Text.from_markup(
                "[dim]Review local accounts for privilege and shell anomalies[/]"
            ),
            title="[bold cyan]USER ACCOUNT SCAN[/]",
            subtitle=f"[dim cyan]{APP_NAME} v{APP_VERSION}[/]",
            border_style="cyan",
            box=box.SQUARE,
            padding=(0, 1),
        )
    )
    console.print()


def _load_valid_shells() -> set[str]:
    try:
        with open("/etc/shells", "r", encoding="utf-8") as file:
            return {
                line.strip()
                for line in file
                if line.strip() and not line.startswith("#")
            }
    except OSError:
        return set()


def _tag_for_reason(reason: str) -> str | None:
    if "UID 0" in reason:
        return "uid0_clone"
    if "Shell access" in reason:
        return "low_uid_shell"
    if "No valid home" in reason:
        return "no_home_dir"
    if "Suspicious shell" in reason:
        return "code_shell"
    if "Non-standard shell" in reason:
        return "nonstandard_shell"
    return None


def _severity(reason: str) -> str:
    if "UID 0" in reason:
        return "[red]CRITICAL[/]"
    if "Shell access" in reason or "Suspicious shell" in reason:
        return "[yellow]WARNING[/]"
    return "[yellow]REVIEW[/]"


def run_user_scan(silent: bool = False):
    if get_os() != "Linux":
        if not silent:
            clear_screen()
            _header()

            console.print(
                Panel.fit(
                    "[yellow]User Account Scan is only supported on Linux.[/]",
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

    flagged = []
    valid_shells = _load_valid_shells()

    try:
        for user in pwd.getpwall():
            username = user.pw_name
            uid = user.pw_uid
            home = user.pw_dir
            shell = user.pw_shell

            if username in KNOWN_SERVICE_USERS:
                continue

            if uid == 0 and username != "root":
                flagged.append((username, "UID 0 (root clone)"))

            if uid < 1000 and shell in INTERACTIVE_SHELLS and username != "root":
                flagged.append((username, f"Shell access on system UID {uid}"))

            if (
                uid >= 1000
                and shell not in NONLOGIN_SHELLS
                and (not home or home in ("/", "/dev/null"))
            ):
                flagged.append((username, "No valid home directory"))

            if shell in ("/usr/bin/python", "/usr/bin/perl", "/dev/null"):
                flagged.append((username, f"Suspicious shell: {shell}"))

            if (
                valid_shells
                and shell
                and shell not in valid_shells
                and shell not in NONLOGIN_SHELLS
            ):
                flagged.append((username, f"Non-standard shell: {shell}"))

    except Exception as e:
        flagged.append(("Error", str(e)))

    unique_accounts = {username for username, _ in flagged if username != "Error"}

    tags = {tag for _, reason in flagged if (tag := _tag_for_reason(reason))}

    if tags:
        tags.add("suspicious_login")

    if silent:
        if not flagged:
            return {
                "status": "ok",
                "details": [],
                "tags": [],
            }

        return {
            "status": "warning",
            "details": [
                f"{len(flagged)} account finding(s) across "
                f"{len(unique_accounts)} account(s)"
            ],
            "tags": sorted(tags),
        }

    clear_screen()
    _header()

    if not flagged:
        console.print(
            Panel.fit(
                "[green]No suspicious account conditions detected.[/]\n"
                "[dim]No UID 0 clones, unusual shells, or invalid homes were found.[/]",
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
            f"[dim]Accounts:[/] [white]{len(unique_accounts)}[/]   "
            f"[dim]Findings:[/] [yellow]{len(flagged)}[/]",
            title="[bold cyan]SUMMARY[/]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )
    console.print()

    table = Table(
        title="[italic cyan]Account Findings[/]",
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
        show_edge=False,
        padding=(0, 1),
    )

    table.add_column("Username", style="cyan", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Reason", style="white")

    for username, reason in flagged:
        table.add_row(
            username,
            _severity(reason),
            reason,
        )

    console.print(table)
    console.print()

    console.print(
        Panel.fit(
            f"[yellow]{len(flagged)} account finding(s) require review.[/]\n"
            "[dim]Validate unexpected privilege, interactive shells, "
            "and abnormal account configuration.[/]",
            title="[bold yellow]REVIEW REQUIRED[/]",
            border_style="yellow",
            box=box.ROUNDED,
        )
    )

    pause_return()

    return {
        "status": "warning",
        "details": [
            f"{len(flagged)} account finding(s) across "
            f"{len(unique_accounts)} account(s)"
        ],
        "tags": sorted(tags),
    }
