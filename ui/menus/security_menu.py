# ui/menus/security_menu.py
# Security Menu
# This module implements the security tools menu for ErisLite, providing access to various security audits and checks. It includes a dashboard showing the last sweep summary and a menu of available security tools,

import json
from pathlib import Path
from textwrap import shorten

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.align import Align
from rich.prompt import Prompt

from ui.utils import clear_screen, show_header, pause_return

from core import (
    security_audit,
    login_audit,
    cve_checker,
)

from tools import (
    integrity_tools,
    listener_check,
    user_anomaly,
    threat_sweep,
    kernel_module_check,
    ssh_key_check,
    ssh_config_check,
    world_writable_check,
    cron_timer_check,
    sweep_viewer,
    suid_check,
    docker_check,
    soc_mode,
)

console = Console()


def get_last_sweep_summary():
    try:
        path = Path.home() / ".erislite" / "last_sweep.json"
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return None


def _score_color(score: int) -> str:
    if score == 0:
        return "grey37"
    if score <= 30:
        return "green"
    if score <= 70:
        return "yellow"
    return "red"


def _render_last_sweep_panel(summary: dict | None) -> None:
    if not summary:
        console.print(Panel.fit(
            "[dim]No previous sweep data available.[/dim]\n"
            "[dim]Tip: press [bold]s[/bold] for Standard sweep.[/dim]",
            title="Last Sweep",
            border_style="grey37"
        ))
        return

    score = int(summary.get("risk_score", 0))
    timestamp = summary.get("timestamp", "Unknown time")
    tags = summary.get("tags", [])
    profile_str = str(summary.get("profile", "unknown")).capitalize()

    color = _score_color(score)

    # keep tags readable in one line; you still save full tags in JSON
    tag_str = ", ".join(tags) if tags else "None"
    tag_str = shorten(tag_str, width=110, placeholder=" …")

    body = (
        f"[bold]Profile:[/] {profile_str}\n"
        f"[bold]Risk Score:[/] [bold {color}]{score}/100[/bold {color}]\n"
        f"[bold]Time:[/] [dim]{timestamp}[/dim]\n"
        f"[bold]Tags:[/] [cyan]{tag_str}[/cyan]"
    )

    console.print(Panel.fit(body, title="Last Sweep", border_style=color))


def _build_menu() -> Table:
    menu = Table(show_header=False, box=None, padding=(0, 1))
    menu.add_row("", "[bold cyan]POSTURE[/bold cyan]")
    menu.add_row("  [1]", "🔍  Posture Snapshot (Fast)")
    menu.add_row("  [13]", "🚨  Run Threat Sweep (profile select)")

    menu.add_row("", "")
    menu.add_row("", "[bold cyan]DETECTION & REVIEW[/bold cyan]")
    menu.add_row("  [2]", "📡  Suspicious Listener Check")
    menu.add_row("  [3]", "🕵️  Hidden / Suspicious User Scan")
    menu.add_row("  [4]", "🔑  SSH Key Enumeration")
    menu.add_row("  [6]", "🧩  Kernel Module Inspection")
    menu.add_row("  [7]", "⏱️  Cron & Timer Inspection")
    menu.add_row("  [12]", "🔐  Login/Auth Log Check")
    menu.add_row("  [14]", "🛡️  CVE Version Scanner (Kernel / Sudo / glibc)")

    menu.add_row("", "")
    menu.add_row("", "[bold cyan]HARDENING SURFACES[/bold cyan]")
    menu.add_row("  [5]", "📂  World-Writable File Scan")
    menu.add_row("  [9]", "⚔️  SUID/SGID Binary Scan")
    menu.add_row("  [10]", "🔧  SSH Config Audit")
    menu.add_row("  [11]", "🐳  Docker Security Check")
    menu.add_row("  [8]", "🧪  File Integrity Monitor")

    menu.add_row("", "")
    menu.add_row("", "[bold cyan]OPS[/bold cyan]")
    menu.add_row("  [15]", "📁  View Recent Threat Sweeps")
    menu.add_row("  [16]", "📡  SOC Mode (15-Min Snapshot)")
    menu.add_row("  [17]", "↩️  Back to Main Menu")

    menu.add_row("", "")
    menu.add_row("", "[bold]Hotkeys[/bold]")
    menu.add_row("[q]", "⚡ Quick Sweep")
    menu.add_row("[s]", "🛡️ Standard Sweep")                     
    menu.add_row("[f]", "🔬 Full Sweep")
    menu.add_row("[r]", "🔁 Rerun last sweep profile (if available)")
    menu.add_row("[b]", "↩️ Back")

    return menu


def run(profile: dict):
    while True:
        clear_screen()
        show_header("SECURITY TOOLS")

        summary = get_last_sweep_summary()
        _render_last_sweep_panel(summary)
        console.print()

        console.print(_build_menu())

        choice = Prompt.ask(
            "\nSelect an option",
            default="b",
            show_default=True
        ).strip().lower()

        # --- Hotkeys ---
        if choice in ("b", "17"):
            break

        if choice in ("q", "s", "f"):
            sweep_profile = {"q": "quick", "s": "standard", "f": "full"}[choice]
            threat_sweep.run_sweep(profile, sweep_profile=sweep_profile)
            continue

        if choice == "r":
            if summary and summary.get("profile"):
                threat_sweep.run_sweep(profile, sweep_profile=str(summary["profile"]).lower())
            else:
                console.print("[yellow]No previous sweep profile found to rerun.[/yellow]")
                pause_return()
            continue

        # --- Numbered actions ---
        if choice == "1":
            security_audit.run(profile)
        elif choice == "2":
            listener_check.run_listener_scan()
        elif choice == "3":
            user_anomaly.run_user_scan()
        elif choice == "4":
            ssh_key_check.run_ssh_key_check()
        elif choice == "5":
            world_writable_check.run_world_writable_check()
        elif choice == "6":
            kernel_module_check.run_kernel_module_check(silent=False)
        elif choice == "7":
            cron_timer_check.run_cron_timer_scan()
        elif choice == "8":
            integrity_tools.integrity_menu()
        elif choice == "9":
            suid_check.run_suid_scan()
        elif choice == "10":
            ssh_config_check.run_ssh_config_check()
        elif choice == "11":
            docker_check.run_docker_scan()
        elif choice == "12":
            login_audit.run_login_audit()
        elif choice == "13":
            # Profile chooser (still available for discoverability)
            clear_screen()
            show_header("THREAT SWEEP")
            sweep_menu = Table(show_header=False, box=None, padding=(0, 1))
            sweep_menu.add_row("[1]", "⚡  Quick – Only checks for open listeners")
            sweep_menu.add_row("[2]", "🛡️  Standard – Listeners, users, login, CVE version")
            sweep_menu.add_row("[3]", "🔬  Full – Extended checks")
            sweep_menu.add_row("[4]", "↩️  Back")
            console.print(sweep_menu)

            sel = Prompt.ask("\nSelect a profile", choices=["1", "2", "3", "4"], default="2")
            if sel == "1":
                threat_sweep.run_sweep(profile, sweep_profile="quick")
            elif sel == "2":
                threat_sweep.run_sweep(profile, sweep_profile="standard")
            elif sel == "3":
                threat_sweep.run_sweep(profile, sweep_profile="full")
            else:
                continue
        elif choice == "14":
            clear_screen()
            show_header("CVE VERSION CHECK")
            cve_checker.run_cve_check()
        elif choice == "15":
            sweep_viewer.sweep_viewer_menu()
        elif choice == "16":
            clear_screen()
            show_header("ERISLITE SOC MODE")
            soc_mode.interactive_soc_mode()
            pause_return()
        else:
            console.print("[red]Invalid option.[/]")
            pause_return()
