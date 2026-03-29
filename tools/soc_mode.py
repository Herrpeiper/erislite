# Project: ErisLITE
# Module: soc_mode.py
# Author: Liam Piper-Brandon
# Version: 0.5
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-03-17
# Description:
#   SOC Mode: A simplified Security Operations Center (SOC) posture assessment tool for Linux systems. It 
#   collects and analyzes recent system logs to provide a high-level overview of the security posture, focusing 
#   on key signals like SSH activity, sudo usage, and system warnings. The module is designed to be accessible and 
#   informative for users without deep security expertise, while still providing actionable insights and context.

import subprocess, shutil, json, os, re

from datetime import datetime
from collections import Counter

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

WINDOW_MINUTES = 15
EXPORT_DIR = "./data/logs/soc_mode"
MAX_DETAIL = 5

console = Console()

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
    logs = collect_journal_logs()
    warn_logs = collect_warning_logs()
    warning_count = len(warn_logs)

    if logs is None:
        console.print(Panel("[red]No journal logs available.[/red]\nTry running ErisLITE with elevated permissions.", title="SOC MODE"))
        return

    parsed = parse_logs(logs)
    status = compute_status(parsed, warning_count)
    score = compute_score(parsed, warning_count)
    attention = build_attention(parsed, warning_count)

    # Color posture
    if status == "STABLE":
        status_color = "green"
    elif status == "WATCH":
        status_color = "yellow"
    else:
        status_color = "red"

    header = (
        f"[bold]Window:[/bold] Last {WINDOW_MINUTES} Minutes\n"
        f"[bold]Timestamp:[/bold] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"[bold]SOC STATUS:[/bold] [{status_color}]{status}[/{status_color}]"
    )
    console.print(Panel(header, title="ERISLITE SOC MODE", expand=False))

    # Summary table
    t = Table(show_header=True, header_style="bold cyan")
    t.add_column("SECTION")
    t.add_column("METRIC")
    t.add_column("VALUE")

    # AUTH
    top_ips_str = "None"
    if parsed["failed_ips_top"]:
        top_ips_str = ", ".join([f"{ip}({cnt})" for ip, cnt in parsed["failed_ips_top"]])

    t.add_row("AUTH", "Failed SSH", f"{parsed['failed_ssh']} (top: {top_ips_str})")
    t.add_row("AUTH", "SSH Success", str(parsed["ssh_success_count"]))
    t.add_row("AUTH", "Sudo Events", str(parsed["sudo_events"]))

    # ROOT ACTIVITY
    t.add_row("ROOT", "Root SSH", str(parsed["root_ssh_success"]))
    t.add_row("ROOT", "su → root", str(parsed["su_to_root"]))
    t.add_row("ROOT", "sudo → root", str(parsed["sudo_to_root"]))

    # SYSTEM
    t.add_row("SYSTEM", "Warnings+", str(warning_count))

    console.print(t)

    # Attention block
    if attention:
        att_text = "\n".join([f"- {x}" for x in attention])
    else:
        att_text = "- None"
    console.print(Panel(att_text, title="ATTENTION", expand=False))

    # Score
    console.print(f"[bold]SOC SCORE:[/bold] {score}/100\n")

    console.print("[1] View Root Details   [2] View Auth Details   [3] Export Snapshot   [4] Return")
    choice = input("> ").strip()

    if choice == "1":
        console.print(Panel(
            "\n".join(
                (["[bold]Root SSH:[/bold]"] + (parsed["root_ssh_details"] or ["(none)"]) + [""] +
                 ["[bold]su → root:[/bold]"] + (parsed["su_to_root_details"] or ["(none)"]) + [""] +
                 ["[bold]sudo → root:[/bold]"] + (parsed["sudo_to_root_details"] or ["(none)"]))
            ),
            title="ROOT DETAILS",
            expand=False
        ))
        input("\nPress Enter to return...")

    elif choice == "2":
        console.print(Panel(
            "\n".join(
                (["[bold]Recent SSH Successes:[/bold]"] + (parsed["ssh_success_raw"] or ["(none)"]) + [""] +
                 ["[bold]Recent sudo events:[/bold]"] + (parsed["sudo_details"] or ["(none)"]))
            ),
            title="AUTH DETAILS",
            expand=False
        ))
        input("\nPress Enter to return...")

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
                "warning_count": warning_count
            }
        }
        path = export_snapshot(snapshot)
        console.print(f"\n[green]Exported to:[/green] {path}\n")
        input("Press Enter to return...")

    # choice "4" or anything else: return to menu
