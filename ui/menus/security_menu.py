# ui/menus/security_menu.py

import json
from pathlib import Path
from textwrap import shorten

from rich.console import Console
from rich.panel import Panel
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
    process_check,
    hosts_check,
    backdoor_check,
    rapid_response,
)

console = Console()

_RULE = "  " + "-" * 52
_COL  = 8   # label starts at this column: "  [13]  " = 8 chars


def _section(label):
    console.print(f"\n  [bold cyan]{label}[/bold cyan]")
    console.print(_RULE)


def _item(key, label):
    # Pad outside the brackets: "  [1]   " and "  [13]  " both put label at column _COL
    bracket = f"[{key}]"
    console.print(f"  {bracket:<{_COL - 2}}{label}")


def _build_menu():
    _section("POSTURE")
    _item("1",  "Posture Snapshot")
    _item("13", "Run Threat Sweep")

    _section("DETECTION & REVIEW")
    _item("2",  "Suspicious Listener Check")
    _item("3",  "Hidden / Suspicious User Scan")
    _item("4",  "SSH Key Enumeration")
    _item("6",  "Kernel Module Inspection")
    _item("7",  "Cron & Timer Inspection")
    _item("12", "Login / Auth Log Check")
    _item("14", "CVE Version Scanner")
    _item("18", "Process Anomaly Scan")
    _item("19", "/etc/hosts Tamper Check")
    _item("20", "Backdoor Detection")

    _section("HARDENING SURFACES")
    _item("5",  "World-Writable File Scan")
    _item("9",  "SUID/SGID Binary Scan")
    _item("10", "SSH Config Audit")
    _item("11", "Docker Security Check")
    _item("8",  "File Integrity Monitor")

    _section("OPS")
    _item("15", "View Recent Threat Sweeps")
    _item("16", "SOC Mode  (15-min snapshot)")
    _item("21", "Rapid Response")
    _item("17", "Back to Main Menu")

    console.print()
    console.print(_RULE)
    console.print(
        "  [bold]Hotkeys[/bold]  "
        "[cyan]q[/cyan]=Quick   "
        "[cyan]s[/cyan]=Standard   "
        "[cyan]f[/cyan]=Full   "
        "[cyan]r[/cyan]=Rerun last   "
        "[cyan]b[/cyan]=Back"
    )
    console.print(_RULE)


# ── Last-sweep panel ───────────────────────────────────────────────────────────

def get_last_sweep_summary():
    try:
        path = Path.home() / ".erislite" / "last_sweep.json"
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return None


def _score_color(score):
    if score == 0:  return "grey37"
    if score <= 30: return "green"
    if score <= 70: return "yellow"
    return "red"


def _render_last_sweep_panel(summary):
    if not summary:
        console.print(Panel.fit(
            "[dim]No previous sweep data.[/dim]  "
            "[dim]Tip: press [bold]s[/bold] for a Standard sweep.[/dim]",
            title="Last Sweep",
            border_style="grey37"
        ))
        return

    score       = int(summary.get("risk_score", 0))
    timestamp   = summary.get("timestamp", "Unknown")
    tags        = summary.get("tags", [])
    profile_str = str(summary.get("profile", "unknown")).capitalize()
    color       = _score_color(score)
    tag_str     = shorten(", ".join(tags) if tags else "None", width=110, placeholder=" ...")

    body = (
        f"[bold]Profile:[/]     {profile_str}\n"
        f"[bold]Risk Score:[/]  [bold {color}]{score}/100[/bold {color}]\n"
        f"[bold]Time:[/]        [dim]{timestamp}[/dim]\n"
        f"[bold]Tags:[/]        [cyan]{tag_str}[/cyan]"
    )
    console.print(Panel.fit(body, title="Last Sweep", border_style=color))


# ── Main loop ──────────────────────────────────────────────────────────────────

def run(profile):
    while True:
        clear_screen()
        show_header("SECURITY TOOLS")

        _render_last_sweep_panel(get_last_sweep_summary())
        _build_menu()

        choice = Prompt.ask(
            "\nSelect an option",
            default="b",
            show_default=True
        ).strip().lower()

        if choice in ("b", "17"):
            break

        if choice in ("q", "s", "f"):
            threat_sweep.run_sweep(profile, sweep_profile={"q": "quick", "s": "standard", "f": "full"}[choice])
            continue

        if choice == "r":
            summary = get_last_sweep_summary()
            if summary and summary.get("profile"):
                threat_sweep.run_sweep(profile, sweep_profile=str(summary["profile"]).lower())
            else:
                console.print("[yellow]No previous sweep profile found.[/yellow]")
                pause_return()
            continue

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
            clear_screen()
            show_header("THREAT SWEEP")
            console.print()
            console.print(_RULE)
            _item("1", "Quick    -- Listeners, users, login")
            _item("2", "Standard -- Integrity, listeners, users, login, CVE")
            _item("3", "Full     -- All checks (SUID, SSH, Docker, kernel)")
            _item("4", "Back")
            console.print(_RULE)
            console.print()
            sel = Prompt.ask("Select a profile", choices=["1", "2", "3", "4"], default="2")
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
        elif choice == "18":
            process_check.run_process_scan()
        elif choice == "19":
            hosts_check.run_hosts_check()
        elif choice == "20":
            backdoor_check.run_backdoor_check()
        elif choice == "21":
            rapid_response.run_rapid_response_menu()
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