# Project: ErisLITE
# Module: security_audit.py
# Author: Liam Piper-Brandon
# Version: 1.3.0-dev
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-14
# Description: Snapshot-style host security posture assessment.

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from erislite.accounts.login_audit import run_login_audit
from erislite.accounts.ssh_keys import run_ssh_key_check
from erislite.config.settings import APP_NAME, APP_VERSION
from erislite.network.firewall import run_firewall_check
from erislite.persistence.world_writable import run_world_writable_check
from erislite.response.security_log import write_audit_log
from erislite.system.processes import run_process_scan
from erislite.ui.console import console
from erislite.ui.utils import clear_screen, pause_return


def _format_result(result: dict, ok_text: str) -> str:
    status = result.get("status", "error")
    details = result.get("details") or []

    if status == "ok":
        return f"🟢 {ok_text}"

    if status == "warning":
        if details:
            return f"[yellow]⚠️ {details[0]}[/]"

        return "[yellow]⚠️ Review required[/]"

    if status == "unsupported":
        return "[yellow]Unsupported on this platform[/]"

    if details:
        return f"⚠️ Error: {details[0]}"

    return "⚠️ Error: inspection incomplete"


def run(profile: dict) -> None:
    clear_screen()

    hostname = profile.get("hostname", "unknown-host")
    role = profile.get("role", "unknown-role")
    analyst_id = profile.get("analyst_id", "N/A")

    header = Panel(
        Text.from_markup(
            f"[dim]Host:[/] [white]{hostname}[/]   "
            f"[dim]Role:[/] [white]{role}[/]   "
            f"[dim]Analyst:[/] [white]{analyst_id}[/]"
        ),
        title="[bold cyan]POSTURE SNAPSHOT[/]",
        subtitle=f"[dim cyan]{APP_NAME} v{APP_VERSION}[/]",
        border_style="cyan",
        box=box.SQUARE,
        padding=(0, 1),
    )

    console.print(header)
    console.print()

    firewall = run_firewall_check(silent=True)
    processes = run_process_scan(silent=True)
    ssh_keys = run_ssh_key_check(silent=True)
    world_writable = run_world_writable_check(silent=True)
    login = run_login_audit(silent=True)

    firewall_status = _format_result(
        firewall,
        "Firewall active",
    )

    proc_status = _format_result(
        processes,
        "No suspicious process conditions detected",
    )

    ssh_key_status = _format_result(
        ssh_keys,
        "No SSH key findings detected",
    )

    writable_status = _format_result(
        world_writable,
        "No high-signal world-writable items detected",
    )

    login_status = _format_result(
        login,
        "No login anomalies detected",
    )

    findings = []

    for label, result in (
        ("Firewall", firewall),
        ("Processes", processes),
        ("SSH Keys", ssh_keys),
        ("World-writable", world_writable),
        ("Auth Logs", login),
    ):
        status = result.get("status", "error")

        if status in ("ok", "unsupported"):
            continue

        details = result.get("details") or ["Inspection incomplete"]

        findings.append(
            f"{label}: " + "; ".join(str(detail) for detail in details)
        )

    table = Table(
        title="[italic cyan]Posture Snapshot — Fast[/]",
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
        show_edge=False,
        padding=(0, 1),
    )

    table.add_column(
        "Check",
        style="cyan",
        no_wrap=True,
        min_width=24,
    )
    table.add_column(
        "Status",
        style="white",
    )

    table.add_row(
        "Firewall",
        firewall_status,
    )
    table.add_row(
        "Suspicious Processes",
        proc_status,
    )
    table.add_row(
        "SSH Authorized Keys",
        ssh_key_status,
    )
    table.add_row(
        "High-Risk World-Writable",
        writable_status,
    )
    table.add_row(
        "Failed SSH Logins",
        login_status,
    )

    console.print(table)

    log_path = write_audit_log(
        profile,
        findings,
    )

    console.print()
    console.print(
        f"[dim]Snapshot saved:[/] [white]{log_path}[/]"
    )
    console.print()

    pause_return()
