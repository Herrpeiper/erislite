# Project: ErisLITE
# Module: soc_mode.py
# Author: Liam Piper-Brandon
# Version: 1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-04-05
# Description: SOC Mode: 15-minute rolling log snapshot and posture assessment.

import json, os, re, shutil, subprocess

from collections import Counter
from datetime import datetime

from rich import box
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from erislite.config.settings import APP_NAME, APP_VERSION
from erislite.ui.console import console
from erislite.ui.utils import clear_screen, pause_return

WINDOW_MINUTES = 15
EXPORT_DIR = "./data/logs/soc_mode"
MAX_DETAIL = 5

# --- Regex (best-effort, stable across common sshd/sudo formats) ---
RE_SSH_FAIL = re.compile(r"Failed password for .* from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})")
RE_SSH_SUCCESS = re.compile(r"Accepted (password|publickey) for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})")
RE_SU_ROOT = re.compile(r"session opened for user root", re.IGNORECASE)
RE_SUDO_USER = re.compile(r"sudo:?\s+(?P<user>[A-Za-z0-9._-]+)\s*:")

# --- Core Functions ---
# Note: All functions are designed to be best-effort and not fail if logs are missing or formats vary.
# The interactive_soc_mode() function is the main entry point for the SOC Mode feature, which can be called from the main menu.
# Logs are collected from journalctl (if available) and parsed for key security signals. The posture status is computed based on simple heuristics, and an interactive report is displayed to the user with options to view details or export a snapshot.

# Helper functions for command execution and availability checks
def _run_cmd(cmd):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode, result.stdout
    except Exception:
        return 1, ""

def _have_cmd(name):
    return shutil.which(name) is not None

# Log collection functions
def collect_journal_logs():
    if not _have_cmd("journalctl"):
        return None

    since = f"{WINDOW_MINUTES} minutes ago"
    code, out = _run_cmd(["journalctl", "--since", since, "--no-pager"])
    if code != 0 or not out.strip():
        return None
    return out.splitlines()

# Collect warnings/errors for system posture context
def collect_warning_logs():
    """Warnings/errors help SOC posture without going 'too detailed'."""
    if not _have_cmd("journalctl"):
        return []
    since = f"{WINDOW_MINUTES} minutes ago"
    code, out = _run_cmd(["journalctl", "--since", since, "-p", "warning..alert", "--no-pager"])
    if code != 0 or not out.strip():
        return []
    return out.splitlines()

# Log parsing function
def parse_logs(lines):
    failed_ssh = 0
    failed_ips = Counter()

    ssh_success_entries = []     # (user, ip, rawline)
    root_ssh_success = 0
    root_ssh_details = []        # raw lines

    sudo_events = 0
    sudo_details = []            # raw lines (last MAX_DETAIL)
    sudo_to_root = 0             # sudo where USER=root (best-effort)
    sudo_to_root_details = []    # raw lines

    su_to_root = 0
    su_to_root_details = []      # raw lines

    for line in lines:
        # SSH fail
        m = RE_SSH_FAIL.search(line)
        if m:
            failed_ssh += 1
            failed_ips[m.group("ip")] += 1

        # SSH success
        m = RE_SSH_SUCCESS.search(line)
        if m:
            user = m.group("user")
            ip = m.group("ip")
            ssh_success_entries.append((user, ip, line.strip()))
            if user == "root":
                root_ssh_success += 1
                root_ssh_details.append(line.strip())
                if len(root_ssh_details) > MAX_DETAIL:
                    root_ssh_details = root_ssh_details[-MAX_DETAIL:]

        # su -> root session opened
        # (common: "su: pam_unix(su:session): session opened for user root by <user>(uid=...)")
        if " su:" in line or line.strip().startswith("su:") or "pam_unix(su:session)" in line:
            if RE_SU_ROOT.search(line):
                su_to_root += 1
                su_to_root_details.append(line.strip())
                if len(su_to_root_details) > MAX_DETAIL:
                    su_to_root_details = su_to_root_details[-MAX_DETAIL:]

        # sudo usage
        if "sudo" in line and "COMMAND=" in line:
            sudo_events += 1
            sudo_details.append(line.strip())
            if len(sudo_details) > MAX_DETAIL:
                sudo_details = sudo_details[-MAX_DETAIL:]

            # sudo to root (best-effort)
            # logs often include "USER=root" when elevating
            if "USER=root" in line:
                sudo_to_root += 1
                sudo_to_root_details.append(line.strip())
                if len(sudo_to_root_details) > MAX_DETAIL:
                    sudo_to_root_details = sudo_to_root_details[-MAX_DETAIL:]

    top_failed_ips = failed_ips.most_common(3)
    # keep only last MAX_DETAIL successes for display
    ssh_success_raw = [x[2] for x in ssh_success_entries[-MAX_DETAIL:]]

    return {
        "failed_ssh": failed_ssh,
        "failed_ips_top": top_failed_ips,
        "ssh_success_count": len(ssh_success_entries),
        "ssh_success_raw": ssh_success_raw,

        "root_ssh_success": root_ssh_success,
        "root_ssh_details": root_ssh_details,

        "sudo_events": sudo_events,
        "sudo_details": sudo_details,
        "sudo_to_root": sudo_to_root,
        "sudo_to_root_details": sudo_to_root_details,

        "su_to_root": su_to_root,
        "su_to_root_details": su_to_root_details,
    }

# Posture computation functions
def compute_status(parsed, warning_count):
    """
    SITREP posture:
    - ACTION REQUIRED: any root escalation signals (root ssh, su->root, sudo->root)
    - WATCH: moderate spikes
    - STABLE: otherwise
    """
    root_activity_total = parsed["root_ssh_success"] + parsed["su_to_root"] + parsed["sudo_to_root"]
    if root_activity_total > 0:
        return "ACTION REQUIRED"

    # WATCH thresholds (simple v1.1)
    if parsed["failed_ssh"] >= 10:
        return "WATCH"
    if parsed["sudo_events"] >= 5:
        return "WATCH"
    if warning_count >= 15:
        return "WATCH"

    return "STABLE"

# Score computation function
# The score is a simple heuristic to give a numeric sense of posture severity. It is not meant to be precise, but to reflect the general level of concern based on the signals detected. The status (STABLE/WATCH/ACTION REQUIRED) is more authoritative for decision-making, while the score provides additional context.
def compute_score(parsed, warning_count):
    """Keep score, but status is authoritative."""
    score = 0

    failed_ssh = parsed["failed_ssh"]
    sudo_events = parsed["sudo_events"]

    if 5 <= failed_ssh <= 10:
        score += 10
    elif 11 <= failed_ssh <= 25:
        score += 20
    elif failed_ssh > 25:
        score += 30

    if parsed["ssh_success_count"] >= 1:
        score += 5
    if parsed["ssh_success_count"] >= 3:
        score += 5

    # sudo is noisy; keep small impact
    if sudo_events >= 5:
        score += 10

    if warning_count >= 15:
        score += 10
    if warning_count >= 30:
        score += 10

    # root activity is critical
    if (parsed["root_ssh_success"] + parsed["su_to_root"] + parsed["sudo_to_root"]) > 0:
        score = max(score, 85)

    return min(score, 100)

# Attention builder function
def build_attention(parsed, warning_count):
    items = []

    if parsed["root_ssh_success"] > 0:
        items.append(f"Root SSH login detected ({parsed['root_ssh_success']})")
    if parsed["su_to_root"] > 0:
        items.append(f"su → root sessions detected ({parsed['su_to_root']})")
    if parsed["sudo_to_root"] > 0:
        items.append(f"sudo → root executions detected ({parsed['sudo_to_root']})")

    if parsed["failed_ssh"] >= 10:
        items.append(f"SSH failure spike ({parsed['failed_ssh']})")

    if parsed["sudo_events"] >= 5:
        items.append(f"High sudo activity ({parsed['sudo_events']})")

    if warning_count >= 15:
        items.append(f"Elevated system warnings ({warning_count})")

    return items

# Export function
def export_snapshot(snapshot):
    os.makedirs(EXPORT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(EXPORT_DIR, f"soc_snapshot_{ts}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=2)
    return path

# --- Main Interactive Function ---
# This function is the main entry point for the SOC Mode feature. It collects logs, parses them, computes the posture status and score, and displays an interactive report to the user. The user can view details about root activity and auth events, or export a snapshot of the current posture for later analysis.
def interactive_soc_mode():
    clear_screen()

    logs = collect_journal_logs()
    warn_logs = collect_warning_logs()
    warning_count = len(warn_logs)

    if logs is None:
        console.print(
            Panel(
                "[yellow]No journal logs available.[/]\n"
                "[dim]Try running ErisLITE with elevated permissions.[/]",
                title="[bold cyan]SOC MODE[/]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )
        pause_return()
        return

    parsed = parse_logs(logs)
    status = compute_status(parsed, warning_count)
    score = compute_score(parsed, warning_count)
    attention = build_attention(parsed, warning_count)

    status_color = {
        "STABLE": "green",
        "WATCH": "yellow",
        "ACTION REQUIRED": "red",
    }.get(status, "white")

    header = Panel(
        Text.from_markup(
            f"[dim]Window:[/] [white]Last {WINDOW_MINUTES} minutes[/]   "
            f"[dim]Timestamp:[/] [white]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/]"
        ),
        title="[bold cyan]ERISLITE SOC MODE[/]",
        subtitle=f"[dim cyan]{APP_NAME} v{APP_VERSION}[/]",
        border_style="cyan",
        box=box.SQUARE,
        padding=(0, 1),
    )

    console.print(header)
    console.print()

    console.print(
        Panel.fit(
            f"[dim]Status:[/] [bold {status_color}]{status}[/]   "
            f"[dim]Score:[/] [bold {status_color}]{score}/100[/]",
            title="[bold cyan]SOC Posture[/]",
            border_style=status_color,
            box=box.ROUNDED,
        )
    )
    console.print()

    top_ips = (
        ", ".join(f"{ip} ({count})" for ip, count in parsed["failed_ips_top"])
        if parsed["failed_ips_top"]
        else "None"
    )

    table = Table(
        title="[italic cyan]Activity Summary[/]",
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
        show_edge=False,
        padding=(0, 1),
    )
    table.add_column("Section", style="cyan", no_wrap=True)
    table.add_column("Metric", style="white")
    table.add_column("Value", style="white")

    table.add_row("AUTH", "Failed SSH", str(parsed["failed_ssh"]))
    table.add_row("AUTH", "Top Failed IPs", top_ips)
    table.add_row("AUTH", "SSH Success", str(parsed["ssh_success_count"]))
    table.add_row("AUTH", "Sudo Events", str(parsed["sudo_events"]))
    table.add_row("ROOT", "Root SSH", str(parsed["root_ssh_success"]))
    table.add_row("ROOT", "su → root", str(parsed["su_to_root"]))
    table.add_row("ROOT", "sudo → root", str(parsed["sudo_to_root"]))
    table.add_row("SYSTEM", "Warnings+", str(warning_count))

    console.print(table)
    console.print()

    if attention:
        attention_text = "\n".join(f"[yellow]•[/] {item}" for item in attention)
        border = "yellow" if status != "ACTION REQUIRED" else "red"
    else:
        attention_text = "[dim]No immediate attention items.[/]"
        border = "grey37"

    console.print(
        Panel.fit(
            attention_text,
            title="[bold cyan]Attention[/]",
            border_style=border,
            box=box.ROUNDED,
        )
    )
    console.print()

    menu = Table(show_header=False, box=None, padding=(0, 1), collapse_padding=True)
    menu.add_column(no_wrap=True)
    menu.add_column()

    menu.add_row("[bold cyan]DETAILS[/]", "")
    menu.add_row("[cyan][1][/]", "View Root Details")
    menu.add_row("[cyan][2][/]", "View Auth Details")
    menu.add_row("[cyan][3][/]", "Export Snapshot")
    menu.add_row("", "")
    menu.add_row("[cyan][0][/]", "Back")

    console.print(menu)

    choice = Prompt.ask(
        "\n[cyan]Select an option[/]",
        default="0",
        show_default=False,
    ).strip()

    if choice == "1":
        console.print()
        console.print(
            Panel(
                "\n".join(
                    ["[bold cyan]Root SSH[/]"]
                    + (parsed["root_ssh_details"] or ["[dim]None[/]"])
                    + [""]
                    + ["[bold cyan]su → root[/]"]
                    + (parsed["su_to_root_details"] or ["[dim]None[/]"])
                    + [""]
                    + ["[bold cyan]sudo → root[/]"]
                    + (parsed["sudo_to_root_details"] or ["[dim]None[/]"])
                ),
                title="[bold cyan]Root Details[/]",
                border_style="cyan",
                box=box.ROUNDED,
            )
        )
        pause_return()

    elif choice == "2":
        console.print()
        console.print(
            Panel(
                "\n".join(
                    ["[bold cyan]Recent SSH Successes[/]"]
                    + (parsed["ssh_success_raw"] or ["[dim]None[/]"])
                    + [""]
                    + ["[bold cyan]Recent sudo Events[/]"]
                    + (parsed["sudo_details"] or ["[dim]None[/]"])
                ),
                title="[bold cyan]Auth Details[/]",
                border_style="cyan",
                box=box.ROUNDED,
            )
        )
        pause_return()

    elif choice == "3":
        snapshot = {
            "timestamp": datetime.now().isoformat(),
            "window_minutes": WINDOW_MINUTES,
            "status": status,
            "score": score,
            "attention": attention,
            "auth": {
                "failed_ssh": parsed["failed_ssh"],
                "failed_ips_top": parsed["failed_ips_top"],
                "ssh_success_count": parsed["ssh_success_count"],
                "ssh_success_recent": parsed["ssh_success_raw"],
                "sudo_events": parsed["sudo_events"],
            },
            "root_activity": {
                "root_ssh_success": parsed["root_ssh_success"],
                "su_to_root": parsed["su_to_root"],
                "sudo_to_root": parsed["sudo_to_root"],
            },
            "system": {
                "warning_count": warning_count,
            },
        }

        path = export_snapshot(snapshot)
        console.print(f"\n[green]Snapshot exported:[/] {path}")
        pause_return()

    # choice "4" or anything else: return to menu
