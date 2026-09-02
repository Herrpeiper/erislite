# Project: ErisLITE
# Module: ssh_config.py
# Author: Liam Piper-Brandon
# Version: 1.1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-02
# Description: sshd_config audit against the ErisLITE hardening baseline.

import os

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from erislite.config.settings import APP_NAME, APP_VERSION
from erislite.ui.console import console
from erislite.ui.utils import clear_screen, get_os, pause_return


SSH_CONFIG_PATH = "/etc/ssh/sshd_config"

SECURE_DEFAULTS = {
    "PermitRootLogin": "no",
    "PasswordAuthentication": "no",
    "PermitEmptyPasswords": "no",
    "ChallengeResponseAuthentication": "no",
    "UsePAM": "yes",
    "X11Forwarding": "no",
    "AllowTcpForwarding": "no",
}


def _header() -> None:
    console.print(
        Panel(
            Text.from_markup(
                "[dim]Audit SSH daemon settings against the ErisLITE hardening baseline[/]"
            ),
            title="[bold cyan]SSH CONFIGURATION CHECK[/]",
            subtitle=f"[dim cyan]{APP_NAME} v{APP_VERSION}[/]",
            border_style="cyan",
            box=box.SQUARE,
            padding=(0, 1),
        )
    )
    console.print()


def parse_sshd_config(path: str = SSH_CONFIG_PATH):
    """
    Parse explicitly configured sshd_config values relevant to the audit.
    """
    if not os.path.exists(path):
        return None

    found = {}

    try:
        with open(
            path,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as file:
            for raw_line in file:
                line = raw_line.strip()

                if not line or line.startswith("#"):
                    continue

                parts = line.split(None, 1)

                if len(parts) < 2:
                    continue

                key = parts[0]
                value = parts[1].split()[0].lower()

                if key in SECURE_DEFAULTS:
                    found[key] = value

    except Exception:
        return None

    return found


def run_ssh_config_check(silent: bool = False):
    if get_os() != "Linux":
        if not silent:
            clear_screen()
            _header()

            console.print(
                Panel.fit(
                    "[yellow]SSH Configuration Check is only supported on Linux.[/]",
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

    config = parse_sshd_config()

    if config is None:
        result = {
            "status": "error",
            "details": [
                f"Unable to read {SSH_CONFIG_PATH}"
            ],
            "tags": ["ssh_config_unreadable"],
            "findings": [],
        }

        if silent:
            return result

        clear_screen()
        _header()

        console.print(
            Panel.fit(
                f"[yellow]Unable to read SSH daemon configuration.[/]\n"
                f"[dim]Path:[/] [white]{SSH_CONFIG_PATH}[/]",
                title="[bold yellow]UNAVAILABLE[/]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )

        pause_return()
        return result

    issues = []
    findings = []

    for key, expected in SECURE_DEFAULTS.items():
        actual = config.get(key)

        if actual is None:
            findings.append(
                {
                    "setting": key,
                    "value": "Not Set",
                    "status": "unset",
                    "expected": expected,
                }
            )
            continue

        if actual != expected:
            issues.append(
                f"{key} is '{actual}' "
                f"(recommended: '{expected}')"
            )

            findings.append(
                {
                    "setting": key,
                    "value": actual,
                    "status": "insecure",
                    "expected": expected,
                }
            )

        else:
            findings.append(
                {
                    "setting": key,
                    "value": actual,
                    "status": "secure",
                    "expected": expected,
                }
            )

    secure_count = sum(
        1
        for finding in findings
        if finding["status"] == "secure"
    )

    insecure_count = sum(
        1
        for finding in findings
        if finding["status"] == "insecure"
    )

    unset_count = sum(
        1
        for finding in findings
        if finding["status"] == "unset"
    )

    result = {
        "status": "warning" if issues else "ok",
        "details": issues,
        "tags": ["weak_ssh_config"] if issues else [],
        "findings": findings,
    }

    if silent:
        return result

    clear_screen()
    _header()

    console.print(
        Panel.fit(
            f"[dim]Secure:[/] [green]{secure_count}[/]   "
            f"[dim]Review:[/] "
            f"[{'yellow' if insecure_count else 'green'}]"
            f"{insecure_count}[/]   "
            f"[dim]Unset:[/] [white]{unset_count}[/]",
            title="[bold cyan]SUMMARY[/]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )
    console.print()

    table = Table(
        title="[italic cyan]SSH Hardening Baseline[/]",
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
        show_edge=False,
        padding=(0, 1),
    )

    table.add_column(
        "Setting",
        style="cyan",
        no_wrap=True,
    )
    table.add_column(
        "Current",
        style="white",
        no_wrap=True,
    )
    table.add_column(
        "Expected",
        style="white",
        no_wrap=True,
    )
    table.add_column(
        "Status",
        no_wrap=True,
    )

    for finding in findings:
        status = finding["status"]

        if status == "secure":
            status_text = "[green]SECURE[/]"

        elif status == "insecure":
            status_text = "[yellow]REVIEW[/]"

        else:
            status_text = "[dim]UNSET[/]"

        table.add_row(
            finding["setting"],
            finding["value"],
            finding["expected"],
            status_text,
        )

    console.print(table)
    console.print()

    if issues:
        console.print(
            Panel.fit(
                f"[yellow]{len(issues)} SSH configuration setting(s) require review.[/]\n"
                "[dim]Validate whether the current values are intentional and appropriate for the host role.[/]",
                title="[bold yellow]REVIEW REQUIRED[/]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )

    else:
        console.print(
            Panel.fit(
                "[green]No explicitly insecure SSH configuration options detected.[/]\n"
                "[dim]Unset values inherit OpenSSH defaults and are shown separately.[/]",
                title="[bold green]STATUS: OK[/]",
                border_style="green",
                box=box.ROUNDED,
            )
        )

    pause_return()
    return result