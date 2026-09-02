# Project: ErisLITE
# Module: viewer.py
# Author: Liam Piper-Brandon
# Version: 1.1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-02
# Description: Threat sweep log viewer for browsing and inspecting saved sweep results.

import json

from rich import box
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from erislite.config.settings import (
    APP_NAME,
    APP_VERSION,
    SWEEP_LOG_DIR,
)
from erislite.sweep.threat_sweep import prioritize_findings
from erislite.ui.console import console
from erislite.ui.utils import clear_screen, pause_return


def _format_risk(data: dict) -> str:
    score = data.get("risk_score")
    maximum = data.get("risk_max")
    percent = data.get("risk_percent")

    if score is None:
        return "N/A"

    if maximum is not None and percent is not None:
        return f"{score}/{maximum} ({percent}%)"

    return str(score)

def _header(title: str) -> None:
    console.print(
        Panel(
            Text.from_markup("[dim]Threat sweep history and report viewer[/]"),
            title=f"[bold cyan]{title}[/]",
            subtitle=f"[dim cyan]{APP_NAME} v{APP_VERSION}[/]",
            border_style="cyan",
            box=box.SQUARE,
            padding=(0, 1),
        )
    )
    console.print()

MODULE_LABELS = {
    "integrity": "Integrity",
    "firewall": "Firewall Status",
    "listeners": "Listeners",
    "users": "User Accounts",
    "kernel": "Kernel Modules",
    "sshkeys": "SSH Keys",
    "worldwritable": "World-Writable Files",
    "cron": "Cron Jobs / Timers",
    "login": "Login / Auth Logs",
    "sshconfig": "SSH Config Audit",
    "docker": "Docker Security",
    "cve": "CVE Version Check",
    "suid": "SUID / SGID Binaries",
    "processes": "Process Anomaly Scan",
    "hosts": "/etc/hosts Tamper Check",
    "backdoor": "Backdoor Detection",
}


def _module_label(module: str) -> str:
    return MODULE_LABELS.get(
        module,
        module.replace("_", " ").title(),
    )


def _get_priorities(data: dict) -> list:
    priorities = data.get("priorities")

    if isinstance(priorities, list):
        return priorities

    return prioritize_findings(
        data.get("results", {})
    )

def _get_profile(data: dict) -> str:
    return str(
        data.get(
            "profile",
            data.get("sweep_profile", "unknown"),
        )
    ).capitalize()

def load_sweep_logs(limit=5):
    if not SWEEP_LOG_DIR.exists():
        return []

    logs = []

    for path in SWEEP_LOG_DIR.glob("sweep_log_*.json"):
        try:
            with open(
                path,
                "r",
                encoding="utf-8",
            ) as file:
                data = json.load(file)

            logs.append(
                (
                    data.get("timestamp", "Unknown"),
                    data,
                    path.name,
                )
            )

        except Exception:
            continue

    logs.sort(
        key=lambda item: item[0],
        reverse=True,
    )

    return logs[:limit]


def show_recent_sweeps(limit=5):
    logs = load_sweep_logs(limit)

    if not logs:
        console.print("[yellow]No recent sweep logs found.[/]")
        return []

    table = Table(
        title=f"[italic cyan]Last {len(logs)} Threat Sweeps[/]",
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
        show_edge=False,
        padding=(0, 1),
    )
    table.add_column("Timestamp", style="white")
    table.add_column("Profile", style="cyan")
    table.add_column("Risk", justify="right")
    table.add_column("Top Priority", style="yellow")
    table.add_column("Tags", style="dim")

    for timestamp, data, _ in logs:
        tag_set = set()

        for result in data.get("results", {}).values():
            tag_set.update(result.get("tags", []))

        tags = ", ".join(sorted(tag_set)) if tag_set else "None"

        priorities = _get_priorities(data)

        if priorities:
            top_priority = _module_label(
                priorities[0]["module"]
            )
        else:
            top_priority = "None"

        table.add_row(
            timestamp,
            _get_profile(data),
            _format_risk(data),
            top_priority,
            tags,
        )

    for result in data.get("results", {}).values():
        tag_set.update(result.get("tags", []))

    tags = ", ".join(sorted(tag_set)) if tag_set else "None"

    priorities = _get_priorities(data)

    if priorities:
        top_priority = _module_label(
            priorities[0]["module"]
        )
    else:
        top_priority = "None"

    table.add_row(
        timestamp,
        _get_profile(data),
        _format_risk(data),
        top_priority,
        tags,
    )

    console.print(table)
    return logs


def view_full_report():
    logs = load_sweep_logs(limit=5)

    if not logs:
        console.print("[yellow]No recent sweep logs found.[/]")
        pause_return()
        return

    clear_screen()
    _header("FULL THREAT SWEEP REPORT")

    table = Table(
        title="[italic cyan]Select a Sweep Log[/]",
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
        show_edge=False,
        padding=(0, 1),
    )
    table.add_column("Index", style="cyan", justify="center")
    table.add_column("Timestamp")
    table.add_column("Profile", style="cyan")
    table.add_column("Risk", justify="right")

    for index, (timestamp, data, _) in enumerate(logs, start=1):
        table.add_row(
            str(index),
            timestamp,
            _get_profile(data),
            _format_risk(data),
        )

    console.print(table)

    choice = Prompt.ask(
        "\n[cyan]Select a log[/]",
        choices=[str(i) for i in range(1, len(logs) + 1)] + ["0"],
        default="0",
    )

    if choice == "0":
        return

    selected = logs[int(choice) - 1][1]
    timestamp = selected.get("timestamp", "Unknown")

    clear_screen()
    _header(f"FULL REPORT — {timestamp}")

    profile = _get_profile(selected)

    risk = _format_risk(selected)

    console.print(
        Panel.fit(
            f"[dim]Profile:[/] [white]{profile}[/]   "
            f"[dim]Risk:[/] [white]{risk}[/]",
            title="[bold cyan]Sweep Metadata[/]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )
    console.print()

    all_tags = set()

    for result in selected.get("results", {}).values():
        all_tags.update(result.get("tags", []))

    if all_tags:
        console.print(f"[dim]Tags:[/] [cyan]{', '.join(sorted(all_tags))}[/]\n")

    priorities = _get_priorities(selected)

    if priorities:
        priority_table = Table(
            title="[italic cyan]Analyst Priority Queue[/]",
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
            show_edge=False,
            padding=(0, 1),
        )

        priority_table.add_column(
            "#",
            style="cyan",
            justify="right",
            no_wrap=True,
        )
        priority_table.add_column(
            "Module",
            style="cyan",
            no_wrap=True,
        )
        priority_table.add_column(
            "Status",
            no_wrap=True,
        )
        priority_table.add_column(
            "Weight",
            justify="right",
            style="yellow",
        )
        priority_table.add_column(
            "Primary Signal",
            style="white",
        )

        for index, finding in enumerate(
            priorities,
            start=1,
        ):
            details = finding.get("details", [])

            primary_signal = (
                details[0]
                if details
                else "Review module findings"
            )

            status = finding.get(
                "status",
                "unknown",
            ).upper()

            priority_table.add_row(
                str(index),
                _module_label(finding["module"]),
                status,
                str(finding.get("weight", 0)),
                primary_signal,
            )

        console.print(priority_table)
        console.print()

    for module, result in selected.get("results", {}).items():
        status = result.get("status", "unknown").lower()
        details = result.get("details") or ["No issues detected."]

        if status == "ok":
            status_text = "[green]OK[/]"
        elif status in ("warning", "issue"):
            status_text = "[yellow]WARNING[/]"
        elif status == "error":
            status_text = "[red]ERROR[/]"
        elif status == "unsupported":
            status_text = "[dim]UNSUPPORTED[/]"
        else:
            status_text = f"[dim]{status.upper()}[/]"

        body = "\n".join(f"[dim]•[/] {line}" for line in details)

        console.print(
            Panel.fit(
                body,
                title=f"[bold cyan]{_module_label(module)}[/]  {status_text}",
                border_style="cyan",
                box=box.ROUNDED,
            )
        )
        console.print()

    pause_return()


def sweep_viewer_menu():
    while True:
        clear_screen()
        _header("SWEEP LOG VIEWER")

        menu = Table(show_header=False, box=None, padding=(0, 1), collapse_padding=True)
        menu.add_column(no_wrap=True)
        menu.add_column()

        menu.add_row("[bold cyan]REVIEW[/]", "")
        menu.add_row("[cyan][1][/]", "View Recent Threat Sweeps")
        menu.add_row("[cyan][2][/]", "View Full Report")
        menu.add_row("", "")
        menu.add_row("[cyan][0][/]", "Back")

        console.print(menu)

        choice = Prompt.ask(
            "\n[cyan]Select an option[/]",
            default="0",
            show_default=False,
        ).strip()

        if choice == "1":
            clear_screen()
            _header("RECENT SWEEP RESULTS")
            show_recent_sweeps()
            pause_return()
        elif choice == "2":
            view_full_report()
        elif choice == "0":
            break
        else:
            console.print("[red]Invalid selection.[/]")
            pause_return()
