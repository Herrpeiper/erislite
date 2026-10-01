# Project: ErisLITE
# Module: security_menu.py
# Author: Liam Piper-Brandon
# Version: 1.4.2
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-10-01
# Description: Security tools menu with threat sweep and posture workflows.

import json
from datetime import datetime

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from erislite.accounts import login_audit, ssh_config, ssh_keys, users
from erislite.config.settings import APP_NAME, APP_VERSION, LAST_SWEEP_FILE
from erislite.containers import docker
from erislite.deception.odyssey import menu as odyssey_menu
from erislite.network import hosts, listeners
from erislite.persistence import backdoors, cron, suid, world_writable
from erislite.response import rapid_response
from erislite.sweep import soc_mode, threat_sweep, viewer
from erislite.system import integrity, kernel_modules, processes, security_audit
from erislite.ui.console import console
from erislite.ui.utils import clear_screen, get_analyst_id, pause_return, prompt_option
from erislite.vulnerability import cve_checker


def get_last_sweep_summary():
    try:
        with open(
            LAST_SWEEP_FILE, "r", encoding="utf-8"
        ) as file:
            return json.load(file)
    except Exception:
        return None


def _score_color(percent: int) -> str:
    if percent == 0:
        return "grey37"
    if percent <= 30:
        return "green"
    if percent <= 70:
        return "yellow"
    return "red"


def _format_sweep_age(timestamp: str) -> str:
    try:
        sweep_time = datetime.fromisoformat(timestamp)
    except (TypeError, ValueError):
        return "Unknown"

    age_seconds = int((datetime.now() - sweep_time).total_seconds())

    if age_seconds < 0:
        return "Just now"

    if age_seconds < 60:
        return "Just now"

    minutes = age_seconds // 60

    if minutes < 60:
        return f"{minutes}m ago"

    hours, minutes = divmod(minutes, 60)

    if hours < 24:
        if minutes:
            return f"{hours}h {minutes}m ago"
        return f"{hours}h ago"

    days, hours = divmod(hours, 24)

    if hours:
        return f"{days}d {hours}h ago"

    return f"{days}d ago"


def _format_risk(summary: dict) -> tuple[str, int]:
    score = summary.get("risk_score")
    maximum = summary.get("risk_max")
    percent = summary.get("risk_percent")

    if score is None:
        return "N/A", 0

    if maximum is not None and percent is not None:
        return f"{score}/{maximum} ({percent}%)", int(percent)

    return str(score), 0


def _render_header(profile: dict) -> None:
    hostname = profile.get("hostname", "unknown-host")
    role = profile.get("role", "unknown-role")
    analyst_id = get_analyst_id(profile)

    metadata_parts = [
        f"[dim]Host:[/] [white]{hostname}[/]",
        f"[dim]Role:[/] [white]{role}[/]",
    ]

    if analyst_id:
        metadata_parts.append(
            f"[dim]Analyst:[/] [white]{analyst_id}[/]"
        )

    metadata = Text.from_markup(
        "   ".join(metadata_parts)
    )

    console.print(
        Panel(
            metadata,
            title="[bold cyan]SECURITY TOOLS[/]",
            subtitle=f"[dim cyan]{APP_NAME} v{APP_VERSION}[/]",
            border_style="cyan",
            box=box.SQUARE,
            padding=(0, 1),
        )
    )
    console.print()


def _render_last_sweep(summary) -> None:
    if not summary:
        console.print(
            Panel.fit(
                "[dim]No previous sweep data[/]   [cyan]s[/]=Standard Sweep",
                title="[dim cyan]Last Sweep[/]",
                border_style="grey37",
                box=box.ROUNDED,
            )
        )
        console.print()
        return

    risk_text, risk_percent = _format_risk(summary)
    profile_name = str(summary.get("profile", "unknown")).capitalize()
    timestamp = summary.get("timestamp", "Unknown")
    sweep_age = _format_sweep_age(timestamp)
    tags = summary.get("tags", [])
    color = _score_color(risk_percent)

    preview = ", ".join(tags[:3]) if tags else "None"
    if len(tags) > 3:
        preview += ", ..."

    body = (
        f"[dim]Profile:[/] [white]{profile_name}[/]   "
        f"[dim]Risk:[/] [bold {color}]{risk_text}[/]   "
        f"[dim]Time:[/] [white]{timestamp}[/]   "
        f"[dim]Age:[/] [cyan]{sweep_age}[/]\n"
        f"[dim]Tags:[/] [white]{len(tags)} indicators[/]   "
        f"[cyan]{preview}[/]"
    )

    console.print(
        Panel.fit(
            body,
            title="[bold cyan]Last Sweep[/]",
            border_style=color,
            box=box.ROUNDED,
        )
    )
    console.print()


def _build_menu() -> Table:
    menu = Table(show_header=False, box=None, padding=(0, 1), collapse_padding=True)
    menu.add_column(no_wrap=True)
    menu.add_column()

    menu.add_row("[bold cyan]POSTURE[/]", "")
    menu.add_row("[cyan][1][/]", "Posture Snapshot")
    menu.add_row("[cyan][2][/]", "Run Threat Sweep")
    menu.add_row("[cyan][3][/]", "View Recent Sweeps")

    menu.add_row("", "")
    menu.add_row("[bold cyan]DETECTION[/]", "")
    menu.add_row("[cyan][4][/]", "Listener Check")
    menu.add_row("[cyan][5][/]", "User Account Scan")
    menu.add_row("[cyan][6][/]", "Process Anomaly Scan")
    menu.add_row("[cyan][7][/]", "Login / Auth Logs")
    menu.add_row("[cyan][8][/]", "Kernel Module Check")

    menu.add_row("", "")
    menu.add_row("[bold cyan]HARDENING[/]", "")
    menu.add_row("[cyan][9][/]", "File Integrity")
    menu.add_row("[cyan][10][/]", "World-Writable Files")
    menu.add_row("[cyan][11][/]", "SUID / SGID Scan")
    menu.add_row("[cyan][12][/]", "Cron / Timer Check")
    menu.add_row("[cyan][13][/]", "SSH Config Audit")

    menu.add_row("", "")
    menu.add_row("[bold cyan]ACCESS / PLATFORM[/]", "")
    menu.add_row("[cyan][14][/]", "SSH Key Check")
    menu.add_row("[cyan][15][/]", "Hosts Tamper Check")
    menu.add_row("[cyan][16][/]", "Docker Security")
    menu.add_row("[cyan][17][/]", "CVE Version Check")
    menu.add_row("[cyan][18][/]", "Backdoor Detection")

    menu.add_row("", "")
    menu.add_row("[bold cyan]RESPONSE[/]", "")
    menu.add_row("[cyan][19][/]", "Rapid Response")
    menu.add_row("[cyan][20][/]", "SOC Mode")

    menu.add_row("", "")
    menu.add_row("[bold cyan]DECEPTION[/]", "")
    menu.add_row("[cyan][21][/]", "Odyssey Lite")

    menu.add_row("", "")
    menu.add_row("[cyan][0][/]", "Back")

    return menu


def _run_sweep_menu(profile: dict) -> None:
    clear_screen()

    console.print(
        Panel(
            "[dim]Select a sweep profile[/]",
            title="[bold cyan]THREAT SWEEP[/]",
            subtitle=f"[dim cyan]{APP_NAME} v{APP_VERSION}[/]",
            border_style="cyan",
            box=box.SQUARE,
        )
    )
    console.print()

    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_row("[cyan][1][/]", "Quick", "[dim]Listeners, users, login[/]")
    table.add_row(
        "[cyan][2][/]", "Standard", "[dim]Integrity, listeners, users, login, CVE[/]"
    )
    table.add_row("[cyan][3][/]", "Full", "[dim]All security checks[/]")
    table.add_row("[cyan][0][/]", "Back", "")

    console.print(table)

    choice = prompt_option()

    if choice == "1":
        threat_sweep.run_sweep(profile, sweep_profile="quick")
    elif choice == "2":
        threat_sweep.run_sweep(profile, sweep_profile="standard")
    elif choice == "3":
        threat_sweep.run_sweep(profile, sweep_profile="full")


def run(profile: dict) -> None:
    while True:
        clear_screen()
        _render_header(profile)
        _render_last_sweep(get_last_sweep_summary())

        console.print(_build_menu())
        console.print()
        console.print(
            "[dim]Hotkeys:[/] "
            "[cyan]q[/] Quick   "
            "[cyan]s[/] Standard   "
            "[cyan]f[/] Full   "
            "[cyan]r[/] Rerun Last"
        )

        choice = prompt_option()

        if choice in ("0", "b"):
            break

        if choice in ("q", "s", "f"):
            profiles = {"q": "quick", "s": "standard", "f": "full"}
            threat_sweep.run_sweep(profile, sweep_profile=profiles[choice])
            continue

        if choice == "r":
            summary = get_last_sweep_summary()

            if summary and summary.get("profile"):
                threat_sweep.run_sweep(
                    profile,
                    sweep_profile=str(summary["profile"]).lower(),
                )
            else:
                console.print("[yellow]No previous sweep profile found.[/]")
                pause_return()

            continue

        if choice == "1":
            security_audit.run(profile)
        elif choice == "2":
            _run_sweep_menu(profile)
        elif choice == "3":
            viewer.sweep_viewer_menu()
        elif choice == "4":
            listeners.run_listener_scan()
        elif choice == "5":
            users.run_user_scan()
        elif choice == "6":
            processes.run_process_scan()
        elif choice == "7":
            login_audit.run_login_audit()
        elif choice == "8":
            kernel_modules.run_kernel_module_check(silent=False)
        elif choice == "9":
            integrity.integrity_menu()
        elif choice == "10":
            world_writable.run_world_writable_check()
        elif choice == "11":
            suid.run_suid_scan()
        elif choice == "12":
            cron.run_cron_timer_scan()
        elif choice == "13":
            ssh_config.run_ssh_config_check()
        elif choice == "14":
            ssh_keys.run_ssh_key_check()
        elif choice == "15":
            hosts.run_hosts_check()
        elif choice == "16":
            docker.run_docker_scan()
        elif choice == "17":
            cve_checker.run_cve_check()
        elif choice == "18":
            backdoors.run_backdoor_check()
        elif choice == "19":
            rapid_response.run_rapid_response_menu()
        elif choice == "20":
            soc_mode.interactive_soc_mode()
        elif choice == "21":
            odyssey_menu.run_odyssey_menu()
        else:
            console.print("[red]Invalid option.[/]")
            pause_return()
