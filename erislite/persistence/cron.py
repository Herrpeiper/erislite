# Project: ErisLITE
# Module: cron.py
# Author: Liam Piper-Brandon
# Version: 1.3.0-dev
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-14
# Description: Cron job and systemd timer inspection for suspicious scheduled tasks.

import os
import pwd
import re
import subprocess
from typing import Dict, List

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from erislite.config.settings import APP_NAME, APP_VERSION
from erislite.security.command_resolver import (
    CommandResolutionError,
    resolve_command,
)
from erislite.ui.console import console
from erislite.ui.utils import clear_screen, get_os, pause_return

SUSPICIOUS_PATTERNS = {
    "reverse_shell": [
        r"\bbash\s+-i\b",
        r"\bnc\s+",
        r"\bncat\b",
        r"\bperl\s+-e\b",
        r"\bpython\d*\b.*\bsocket\b",
        r"0<&196;",
        r"/dev/tcp/",
        r"/dev/udp/",
    ],
    "external_payload": [
        r"\bwget\s+",
        r"\bcurl\s+",
        r"\bscp\s+",
        r"\bftp\s+",
    ],
    "encoded_execution": [
        r"\bbase64\s+(?:-d|--decode)\b",
        r"\bbase64\b.*\|\s*(?:sh|bash)\b",
        r"\beval\s+\$\((?:curl|wget)\b",
    ],
    "temp_execution": [
        r"/tmp/",
        r"/var/tmp/",
        r"/dev/shm/",
    ],
    "hidden_execution": [
        r"/\.[^/\s]+",
    ],
    "shell_execution": [
        r"\b(?:sh|bash)\s+-c\b.*(?:/tmp/|/dev/shm/|/var/tmp/)",
        r"\b(?:sh|bash)\s+-c\b.*(?:curl|wget|nc|ncat)\b",
    ],
}

SYSTEM_CRONTABS = (
    "/etc/crontab",
    "/etc/cron.d",
)

PERIODIC_CRON_DIRS = (
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
)

def _collection_error(source: str, reason: str) -> Dict:
    return {
        "type": "Collection Error",
        "path": source,
        "owner": "-",
        "line": "-",
        "command": reason,
        "tags": ["cron_scan_incomplete"],
        "kind": "error",
    }

def _header() -> None:
    console.print(
        Panel(
            Text.from_markup(
                "[dim]Inspect cron jobs and systemd timers for suspicious persistence or execution[/]"
            ),
            title="[bold cyan]CRON / TIMER CHECK[/]",
            subtitle=f"[dim cyan]{APP_NAME} v{APP_VERSION}[/]",
            border_style="cyan",
            box=box.SQUARE,
            padding=(0, 1),
        )
    )
    console.print()

def tag_command(command: str) -> List[str]:
    tags = []
    command_lower = command.lower()

    for label, patterns in SUSPICIOUS_PATTERNS.items():
        for pattern in patterns:
            try:
                if re.search(pattern, command_lower, re.IGNORECASE):
                    tags.append(label)
                    break
            except re.error:
                continue

    return tags

def _file_owner(path: str) -> str:
    try:
        uid = os.stat(path).st_uid
        return pwd.getpwuid(uid).pw_name
    except Exception:
        return "unknown"

def _parse_system_crontab(path: str) -> List[Dict]:
    """
    Parse /etc/crontab and /etc/cron.d/*.

    Format:
        min hour dom month dow user command...
    """
    flagged = []

    try:
        with open(
            path,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as file:
            for lineno, raw_line in enumerate(file, 1):
                line = raw_line.strip()

                if not line or line.startswith("#"):
                    continue

                if "=" in line and not line.startswith("@"):
                    first_token = line.split()[0]

                    if "=" in first_token:
                        continue

                if line.startswith("@"):
                    tokens = line.split(None, 2)

                    if len(tokens) < 3:
                        continue

                    owner = tokens[1]
                    command = tokens[2]

                else:
                    tokens = line.split()

                    if len(tokens) < 7:
                        continue

                    owner = tokens[5]
                    command = " ".join(tokens[6:])

                tags = tag_command(command)

                if tags:
                    flagged.append(
                        {
                            "type": "Cron",
                            "path": path,
                            "owner": owner,
                            "line": lineno,
                            "command": command,
                            "tags": tags,
                        }
                    )

    except OSError as exc:
        flagged.append(
            _collection_error(
                path,
                f"Could not read crontab: {exc}",
            )
        )

    return flagged

def _inspect_periodic_scripts() -> List[Dict]:
    flagged = []

    for directory in PERIODIC_CRON_DIRS:
        if not os.path.isdir(directory):
            continue

        try:
            entries = os.listdir(directory)
        except OSError as exc:
            flagged.append(
                _collection_error(
                    directory,
                    f"Could not enumerate periodic cron directory: {exc}",
                )
            )
            continue

        for name in entries:
            path = os.path.join(directory, name)

            if not os.path.isfile(path) or os.path.islink(path):
                continue

            try:
                with open(
                    path,
                    "r",
                    encoding="utf-8",
                    errors="ignore",
                ) as file:
                    content = file.read()

                tags = tag_command(content)

                if tags:
                    flagged.append(
                        {
                            "type": "Periodic Script",
                            "path": path,
                            "owner": _file_owner(path),
                            "line": "-",
                            "command": _first_interesting_line(content),
                            "tags": tags,
                        }
                    )

            except FileNotFoundError:
                continue

            except OSError as exc:
                flagged.append(
                    _collection_error(
                        path,
                        f"Could not inspect periodic cron script: {exc}",
                    )
                )

    return flagged

def _first_interesting_line(content: str) -> str:
    for raw_line in content.splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        if tag_command(line):
            return line[:180]

    return "Suspicious pattern detected in script"

def check_cron_jobs() -> List[Dict]:
    flagged = []

    if os.path.isfile("/etc/crontab"):
        flagged.extend(
            _parse_system_crontab("/etc/crontab")
        )

    if os.path.isdir("/etc/cron.d"):
        try:
            for name in os.listdir("/etc/cron.d"):
                path = os.path.join("/etc/cron.d", name)

                if os.path.isfile(path):
                    flagged.extend(
                        _parse_system_crontab(path)
                    )
        except OSError as exc:
            flagged.append(
                _collection_error(
                    "/etc/cron.d",
                    f"Could not enumerate cron directory: {exc}",
                )
            )

    flagged.extend(_inspect_periodic_scripts())

    return flagged

def check_user_crontabs() -> List[Dict]:
    flagged = []

    try:
        crontab = resolve_command("crontab")

    except CommandResolutionError:
        return [
            _collection_error(
                "user crontabs",
                "crontab command is unavailable",
            )
        ]

    try:
        users = pwd.getpwall()

    except Exception as exc:
        return [
            _collection_error(
                "/etc/passwd",
                f"Could not enumerate users for crontab inspection: {exc}",
            )
        ]

    for user in users:
        if user.pw_uid < 1000:
            continue

        try:
            result = subprocess.run(
                [
                    crontab,
                    "-l",
                    "-u",
                    user.pw_name,
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode != 0:
                continue

            for lineno, raw_line in enumerate(
                result.stdout.splitlines(),
                1,
            ):
                line = raw_line.strip()

                if not line or line.startswith("#"):
                    continue

                if "=" in line and not line.startswith("@"):
                    first_token = line.split()[0]

                    if "=" in first_token:
                        continue

                if line.startswith("@"):
                    tokens = line.split(None, 1)

                    if len(tokens) < 2:
                        continue

                    command = tokens[1]

                else:
                    tokens = line.split()

                    if len(tokens) < 6:
                        continue

                    command = " ".join(tokens[5:])

                tags = tag_command(command)

                if tags:
                    flagged.append(
                        {
                            "type": "User Cron",
                            "path": f"crontab -u {user.pw_name}",
                            "owner": user.pw_name,
                            "line": lineno,
                            "command": command,
                            "tags": tags,
                        }
                    )

        except subprocess.TimeoutExpired:
            flagged.append(
                _collection_error(
                    f"crontab -u {user.pw_name}",
                    "User crontab inspection timed out",
                )
            )

        except Exception:
            continue

    return flagged


def check_systemd_timers() -> List[Dict]:
    try:
        systemctl = resolve_command("systemctl")
    except CommandResolutionError:
        return [
            _collection_error(
                "systemd timers",
                "systemctl is unavailable",
            )
        ]

    try:
        result = subprocess.run(
            [
                systemctl,
                "list-timers",
                "--all",
                "--no-pager",
                "--no-legend",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode != 0:
            return [
                _collection_error(
                    "systemd timers",
                    result.stderr.strip()
                    or f"systemctl list-timers exited with code {result.returncode}",
                )
            ]

    except subprocess.TimeoutExpired:
        return [
            _collection_error(
                "systemd timers",
                "systemctl list-timers timed out",
            )
        ]

    except OSError as exc:
        return [
            _collection_error(
                "systemd timers",
                f"Could not inspect systemd timers: {exc}",
            )
        ]

    flagged = []

    for line in result.stdout.splitlines():
        line = line.strip()

        if not line:
            continue

        timer_match = re.search(
            r"(\S+\.timer)\s+\S*\.service",
            line,
        )

        if timer_match:
            timer = timer_match.group(1)
        else:
            candidates = [
                part
                for part in line.split()
                if part.endswith(".timer")
            ]

            if not candidates:
                continue

            timer = candidates[0]

        try:
            show = subprocess.run(
                [
                    systemctl,
                    "show",
                    timer,
                    "-p",
                    "FragmentPath",
                    "-p",
                    "Triggers",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if show.returncode != 0:
                continue

            properties = {}

            for prop_line in show.stdout.splitlines():
                if "=" in prop_line:
                    key, value = prop_line.split("=", 1)
                    properties[key] = value

            timer_path = properties.get(
                "FragmentPath",
                "",
            )

            service_names = properties.get(
                "Triggers",
                "",
            ).split()

            for service in service_names:
                if not service.endswith(".service"):
                    continue

                service_result = subprocess.run(
                    [
                        systemctl,
                        "show",
                        service,
                        "-p",
                        "FragmentPath",
                        "-p",
                        "ExecStart",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )

                if service_result.returncode != 0:
                    continue

                service_props = {}

                for prop_line in service_result.stdout.splitlines():
                    if "=" in prop_line:
                        key, value = prop_line.split("=", 1)
                        service_props[key] = value

                service_path = service_props.get(
                    "FragmentPath",
                    "",
                )

                exec_start = service_props.get(
                    "ExecStart",
                    "",
                )

                tags = tag_command(exec_start)

                nonstandard_path = (
                    service_path.startswith("/tmp/")
                    or service_path.startswith("/var/tmp/")
                    or service_path.startswith("/dev/shm/")
                    or service_path.startswith("/home/")
                )

                user_owned = False
                owner = "root"

                if service_path and os.path.exists(service_path):
                    try:
                        uid = os.stat(service_path).st_uid
                        owner = pwd.getpwuid(uid).pw_name
                        user_owned = uid >= 1000
                    except Exception:
                        pass

                if nonstandard_path:
                    tags.append("nonstandard_timer_path")

                if user_owned:
                    tags.append("user_owned_timer")

                if tags:
                    flagged.append(
                        {
                            "type": "Systemd Timer",
                            "path": timer_path or timer,
                            "owner": owner,
                            "line": "-",
                            "command": exec_start or service,
                            "tags": sorted(set(tags)),
                        }
                    )

        except Exception:
            continue

    return flagged

def check_windows_scheduled_tasks() -> List[Dict]:
    flagged = []

    try:
        schtasks = resolve_command("schtasks")
    except CommandResolutionError:
        return [
            _collection_error(
                "Windows scheduled tasks",
                "schtasks is unavailable",
            )
        ]

    try:
        result = subprocess.run(
            [
                schtasks,
                "/query",
                "/fo",
                "LIST",
                "/v",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )

        if result.returncode != 0:
            return [
                _collection_error(
                    "Windows scheduled tasks",
                    result.stderr.strip()
                    or f"schtasks exited with code {result.returncode}",
                )
            ]

        tasks = re.split(
            r"\r?\n\r?\n",
            result.stdout.strip(),
        )

        for task in tasks:
            props = {}

            for line in task.splitlines():
                if ":" not in line:
                    continue

                key, value = line.split(":", 1)
                props[key.strip()] = value.strip()

            command = props.get("Task To Run", "")

            if not command:
                continue

            tags = tag_command(command)

            if tags:
                flagged.append(
                    {
                        "type": "Scheduled Task",
                        "path": props.get(
                            "TaskName",
                            "Unknown",
                        ),
                        "owner": props.get(
                            "Run As User",
                            "Unknown",
                        ),
                        "line": "-",
                        "command": command,
                        "tags": tags,
                    }
                )

    except subprocess.TimeoutExpired:
        flagged.append(
            _collection_error(
                "Windows scheduled tasks",
                "schtasks query timed out",
            )
        )

    except OSError as exc:
        flagged.append(
            _collection_error(
                "Windows scheduled tasks",
                f"Could not inspect scheduled tasks: {exc}",
            )
        )

    return flagged

def run_cron_timer_scan(silent: bool = False):
    os_type = get_os()

    findings = []

    if os_type == "Linux":
        findings.extend(check_cron_jobs())
        findings.extend(check_user_crontabs())
        findings.extend(check_systemd_timers())

    elif os_type == "Windows":
        findings.extend(
            check_windows_scheduled_tasks()
        )

    else:
        if not silent:
            clear_screen()
            _header()

            console.print(
                Panel.fit(
                    "[yellow]Cron / Timer Check is not supported on this platform.[/]",
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

    errors = [
        entry
        for entry in findings
        if entry.get("kind") == "error"
    ]

    scheduled_findings = [
        entry
        for entry in findings
        if entry.get("kind") != "error"
    ]

    total = len(scheduled_findings)

    if scheduled_findings:
        status = "warning"
    elif errors:
        status = "error"
    else:
        status = "ok"

    details = []

    if scheduled_findings:
        details.append(
            f"{total} suspicious scheduled task(s) flagged"
        )

    if errors:
        details.extend(
            f"{entry['path']} — {entry['command']}"
            for entry in errors
        )

    tags = []

    if scheduled_findings:
        tags.append("suspicious_cron")

    if errors:
        tags.append("cron_scan_incomplete")

    result = {
        "status": status,
        "details": details,
        "tags": tags,
    }

    if silent:
        return result

    clear_screen()
    _header()

    console.print(
        Panel.fit(
            f"[dim]Findings:[/] "
            f"[{'yellow' if scheduled_findings else 'green'}]{total}[/]   "
            f"[dim]Platform:[/] [white]{os_type}[/]",
            title="[bold cyan]SUMMARY[/]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )
    console.print()

    if scheduled_findings:
        table = Table(
            title="[italic cyan]Scheduled Task Findings[/]",
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
            show_edge=False,
            padding=(0, 1),
        )

        table.add_column("Type", style="cyan", no_wrap=True)
        table.add_column("Path / Task", style="white")
        table.add_column("Owner", style="white", no_wrap=True)
        table.add_column("Signals", style="yellow")

        for entry in scheduled_findings:
            table.add_row(
                entry["type"],
                entry["path"],
                entry["owner"],
                ", ".join(entry["tags"]),
            )

        console.print(table)
        console.print()

    if errors:
        error_table = Table(
            title="[italic cyan]Collection Issues[/]",
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
            show_edge=False,
            padding=(0, 1),
        )

        error_table.add_column("Source", style="white")
        error_table.add_column("Issue", style="yellow")

        for entry in errors:
            error_table.add_row(
                entry["path"],
                entry["command"],
            )

        console.print(error_table)
        console.print()

    if scheduled_findings:
        console.print(
            Panel.fit(
                f"[yellow]{total} scheduled task(s) require review.[/]\n"
                "[dim]Validate command content, ownership, execution path, and whether the schedule is expected.[/]",
                title="[bold yellow]REVIEW REQUIRED[/]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )

    elif errors:
        console.print(
            Panel.fit(
                "[yellow]Scheduled-task inspection completed with collection errors.[/]\n"
                "[dim]Results may be incomplete; review unavailable sources.[/]",
                title="[bold yellow]INCOMPLETE[/]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )

    else:
        console.print(
            Panel.fit(
                "[green]No suspicious scheduled-task signals detected.[/]\n"
                "[dim]Cron entries and timer-backed services did not match the current detection rules.[/]",
                title="[bold green]STATUS: OK[/]",
                border_style="green",
                box=box.ROUNDED,
            )
        )

    pause_return()
    return result