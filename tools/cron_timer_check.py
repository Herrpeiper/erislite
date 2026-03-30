# Project: ErisLITE
# Module: cron_timer_check.py
# Author: Liam Piper-Brandon
# Version: 0.7
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-03-29
# Description: Cron job and systemd timer inspection for suspicious scheduled tasks.

import os, stat, pwd, subprocess, re

from rich.console import Console
from rich.table import Table

from ui.utils import clear_screen, show_header, pause_return, get_os

console = Console()

# Define patterns to look for in scheduled tasks that may indicate malicious activity
SUSPICIOUS_PATTERNS = {
    "reverse_shell": [r"bash\s+-i", r"nc\s", r"ncat", r"perl\s+-e", r"python.*socket", r"0<&196;"],
    "external_payload": [r"wget\s", r"curl\s", r"scp\s", r"ftp\s"],
    "encoded_execution": [r"base64\s+-d", r"eval\s", r"sh\s+-c"],
    "temp_execution": [r"/tmp/", r"/dev/shm/", r"\.hidden", r"\.config"]
}

# Tag a command based on suspicious patterns
def tag_command(cmd):
    tags = []
    for label, patterns in SUSPICIOUS_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, cmd):
                tags.append(label)
                break
    return tags

# Check system cron jobs and scheduled tasks
def check_cron_jobs():
    cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
                 "/etc/cron.monthly", "/etc/cron.weekly", "/var/spool/cron"]
    flagged = []

    for directory in cron_dirs:
        if os.path.exists(directory):
            for root, _, files in os.walk(directory):
                for file in files:
                    path = os.path.join(root, file)
                    try:
                        with open(path, 'r', errors='ignore') as f:
                            for lineno, line in enumerate(f, 1):
                                line = line.strip()
                                if not line or line.startswith("#"):
                                    continue
                                tokens = line.split()
                                if len(tokens) < 6:
                                    continue
                                # Cron format: [minute] [hour] [dom] [month] [dow] [command...]
                                cmd = " ".join(tokens[5:])
                                tags = tag_command(cmd)
                                if tags:
                                    stat_info = os.stat(path)
                                    uid = stat_info.st_uid
                                    owner = pwd.getpwuid(uid).pw_name
                                    flagged.append({
                                        "path": path,
                                        "owner": owner,
                                        "line": lineno,
                                        "command": cmd,
                                        "tags": tags
                                    })
                    except Exception:
                        continue
    return flagged

# Check user-specific crontabs
def check_user_crontabs():
    flagged = []
    for user in pwd.getpwall():
        if user.pw_uid < 1000:
            continue  # Skip system users
        try:
            output = subprocess.check_output(
                ["crontab", "-l", "-u", user.pw_name],
                stderr=subprocess.DEVNULL
            ).decode().splitlines()

            for lineno, line in enumerate(output, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                tokens = line.split()
                if len(tokens) < 6:
                    continue
                cmd = " ".join(tokens[5:])
                tags = tag_command(cmd)
                if tags:
                    flagged.append({
                        "path": f"crontab -u {user.pw_name}",
                        "owner": user.pw_name,
                        "line": lineno,
                        "command": cmd,
                        "tags": tags
                    })
        except subprocess.CalledProcessError:
            continue  # User has no crontab
        except Exception:
            continue
    return flagged

# Check systemd timers for suspicious services
def check_systemd_timers():
    try:
        output = subprocess.check_output(
            ["systemctl", "list-timers", "--all", "--no-pager", "--no-legend"],
            stderr=subprocess.DEVNULL
        ).decode()

        flagged = []
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) < 6:
                continue
            timer = parts[5]  # UNIT column is 6th field
            if timer.endswith('.timer'):
                service = timer.replace('.timer', '.service')
                try:
                    svc_path = subprocess.check_output(
                        ["systemctl", "show", "-p", "FragmentPath", service],
                        stderr=subprocess.DEVNULL
                    ).decode().strip().split('=')[-1]
                    if svc_path and os.path.exists(svc_path):
                        stat_info = os.stat(svc_path)
                        uid = stat_info.st_uid
                        owner = pwd.getpwuid(uid).pw_name
                        if uid >= 1000 or "/tmp/" in svc_path or "/home/" in svc_path:
                            flagged.append((service, svc_path, owner))
                except Exception:
                    continue
        return flagged
    except Exception:
        return []

# Check Windows scheduled tasks for suspicious commands    
def check_windows_scheduled_tasks():
    flagged = []
    try:
        output = subprocess.check_output(
            ["schtasks", "/query", "/fo", "LIST", "/v"],
            stderr=subprocess.DEVNULL,
            text=True
        )

        # Split into sections per task
        tasks = output.strip().split("\n\n")
        for task in tasks:
            lines = [line.strip() for line in task.splitlines() if line.strip()]
            props = {}
            for line in lines:
                if ":" in line:
                    k, v = line.split(":", 1)
                    props[k.strip()] = v.strip()
            command = props.get("Task To Run", "")
            if command:
                tags = tag_command(command)
                if tags:
                    flagged.append({
                        "path": props.get("TaskName", ""),
                        "owner": props.get("Run As User", ""),
                        "command": command,
                        "tags": tags
                    })
    except Exception:
        pass
    return flagged

# Main function to run the cron and timer scan
def run_cron_timer_scan(silent=False):
    os_type = get_os()

    cron_flags = []
    timer_flags = []

    if os_type == "Linux":
        cron_flags = check_cron_jobs()
        user_cron_flags = check_user_crontabs()
        cron_flags.extend(user_cron_flags)
        timer_flags = check_systemd_timers()
    elif os_type == "Windows":
        cron_flags = check_windows_scheduled_tasks()
    else:
        if not silent:
            console.print("[yellow]This module is not supported on this OS.[/]")
            pause_return()
        return {
            "status": "unsupported",
            "details": [],
            "tags": []
        }

    total = len(cron_flags) + len(timer_flags)

    if not silent:
        clear_screen()
        show_header("SUSPICIOUS SCHEDULED TASK CHECK")

        table = Table(title="Potentially Malicious Scheduled Tasks", show_lines=True)
        table.add_column("Type", style="yellow")
        table.add_column("Path / Task", style="magenta")
        table.add_column("Owner", style="cyan")

        for entry in cron_flags:
            table.add_row("Cron/Scheduled Task", entry['path'], entry['owner'])
        for service, path, owner in timer_flags:
            table.add_row("Systemd Timer", f"{service}\n→ {path}", owner)

        if total > 0:
            console.print(table)
        else:
            console.print("[green]No suspicious scheduled tasks found.[/]")
        pause_return()

    if total > 0:
        return {
            "status": "warning",
            "details": [f"{total} suspicious scheduled tasks flagged"],
            "tags": ["suspicious_cron"]
        }
    else:
        return {
            "status": "ok",
            "details": [],
            "tags": []
        }

