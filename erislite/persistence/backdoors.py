# Project: ErisLITE
# Module: backdoors.py
# Author: Liam Piper-Brandon
# Version: 1.1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-02
# Description: Shell init, profile, and LD_PRELOAD persistence inspection.

import os
import pwd
import re

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from erislite.config.settings import APP_NAME, APP_VERSION
from erislite.ui.console import console
from erislite.ui.utils import clear_screen, get_os, pause_return

SUSPICIOUS_PATTERNS = [
    (re.compile(r"\bnc\b.*(?:-e|--exec|-c)\b", re.I), "Netcat execution"),
    (re.compile(r"\bncat\b.*(?:-e|--exec|-c)\b", re.I), "Ncat execution"),
    (re.compile(r"\bsocat\b.*EXEC:", re.I), "Socat execution"),
    (
        re.compile(r"/dev/tcp/(?:\d{1,3}\.){3}\d{1,3}/\d+", re.I),
        "Bash TCP connection",
    ),
    (
        re.compile(r"\bcurl\b.*\|\s*(?:sh|bash|python\d*)\b", re.I),
        "Downloaded content piped to interpreter",
    ),
    (
        re.compile(r"\bwget\b.*\|\s*(?:sh|bash|python\d*)\b", re.I),
        "Downloaded content piped to interpreter",
    ),
    (
        re.compile(r"\bbase64\b.*(?:-d|--decode).*\|\s*(?:sh|bash)\b", re.I),
        "Decoded content piped to shell",
    ),
    (
        re.compile(r"\bpython\d*\b\s+-c\b.*(?:socket|subprocess|pty)", re.I),
        "Suspicious Python one-liner",
    ),
    (
        re.compile(r"\bperl\b\s+-e\b.*(?:socket|exec)", re.I),
        "Suspicious Perl one-liner",
    ),
    (
        re.compile(r"\bruby\b\s+-e\b.*(?:socket|exec)", re.I),
        "Suspicious Ruby one-liner",
    ),
    (
        re.compile(r"\bnohup\b.*(?:/tmp/|/dev/shm/|/var/tmp/)", re.I),
        "Nohup execution from temporary path",
    ),
    (re.compile(r"\bLD_PRELOAD\s*=", re.I), "LD_PRELOAD override"),
]


SYSTEM_INIT_FILES = [
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/bashrc",
    "/etc/environment",
    "/etc/zshrc",
    "/etc/zshenv",
]

SYSTEM_INIT_DIRS = [
    "/etc/profile.d",
    "/etc/update-motd.d",
]

USER_INIT_FILES = [
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".profile",
    ".zshrc",
    ".zshenv",
    ".zprofile",
    ".xinitrc",
    ".xsession",
    ".config/autostart",
]

SNAP_PRELOAD_WHITELIST = (
    "/snap/",
    "/var/lib/snapd/",
)

BARE_LIB_WHITELIST = {
    "libmozsandbox.so",
    "bindtextdomain.so",
}


def _header() -> None:
    console.print(
        Panel(
            Text.from_markup(
                "[dim]Inspect shell initialization and preload mechanisms for persistence indicators[/]"
            ),
            title="[bold cyan]BACKDOOR DETECTION[/]",
            subtitle=f"[dim cyan]{APP_NAME} v{APP_VERSION}[/]",
            border_style="cyan",
            box=box.SQUARE,
            padding=(0, 1),
        )
    )
    console.print()


def _finding(
    location: str,
    reason: str,
    tag: str,
    content: str = "",
) -> dict:
    return {
        "location": location,
        "reason": reason,
        "tag": tag,
        "line": content,
        "kind": "finding",
    }


def _error(location: str, reason: str) -> dict:
    return {
        "location": location,
        "reason": reason,
        "tag": "backdoor_read_error",
        "line": "",
        "kind": "error",
    }


def _check_ld_preload() -> list:
    findings = []
    path = "/etc/ld.so.preload"

    if not os.path.exists(path):
        return findings

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

                findings.append(
                    _finding(
                        path,
                        f"Library injected via ld.so.preload: {line}",
                        "backdoor_ld_preload",
                        line,
                    )
                )

    except Exception as exc:
        findings.append(
            _error(
                path,
                f"Could not read {path}: {exc}",
            )
        )

    return findings


def _check_env_ld_preload() -> list:
    findings = []

    try:
        proc_entries = os.scandir("/proc")
    except Exception:
        return findings

    with proc_entries:
        for entry in proc_entries:
            if not entry.is_dir() or not entry.name.isdigit():
                continue

            env_path = f"/proc/{entry.name}/environ"

            try:
                with open(env_path, "rb") as file:
                    env = file.read().decode(
                        "utf-8",
                        errors="replace",
                    )

            except (PermissionError, FileNotFoundError):
                continue

            except Exception:
                continue

            for variable in env.split("\x00"):
                if not variable.startswith("LD_PRELOAD="):
                    continue

                value = variable.split("=", 1)[1]

                libraries = [
                    lib
                    for lib in re.split(r"[ :]", value)
                    if lib
                ]

                suspicious = [
                    lib
                    for lib in libraries
                    if not any(
                        lib.startswith(prefix)
                        for prefix in SNAP_PRELOAD_WHITELIST
                    )
                    and lib not in BARE_LIB_WHITELIST
                ]

                if suspicious:
                    findings.append(
                        _finding(
                            f"PID {entry.name} environment",
                            "LD_PRELOAD active with unrecognized library",
                            "backdoor_ld_preload_env",
                            ", ".join(suspicious),
                        )
                    )

                break

    return findings


def _scan_file(path: str) -> list:
    findings = []

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

                for pattern, label in SUSPICIOUS_PATTERNS:
                    if pattern.search(line):
                        findings.append(
                            _finding(
                                f"{path}:{lineno}",
                                label,
                                "backdoor_init_file",
                                line[:160],
                            )
                        )
                        break

    except (PermissionError, FileNotFoundError):
        pass

    except Exception as exc:
        findings.append(
            _error(
                path,
                f"Read error: {exc}",
            )
        )

    return findings


def _scan_dir(directory: str) -> list:
    findings = []

    if not os.path.isdir(directory):
        return findings

    try:
        for entry in os.scandir(directory):
            if entry.is_file(follow_symlinks=False):
                findings.extend(
                    _scan_file(entry.path)
                )

    except PermissionError:
        pass

    except Exception as exc:
        findings.append(
            _error(
                directory,
                f"Directory scan error: {exc}",
            )
        )

    return findings


def scan_backdoors() -> list:
    findings = []

    for path in SYSTEM_INIT_FILES:
        if os.path.isfile(path):
            findings.extend(
                _scan_file(path)
            )

    for directory in SYSTEM_INIT_DIRS:
        findings.extend(
            _scan_dir(directory)
        )

    try:
        users = pwd.getpwall()
    except Exception:
        users = []

    for user in users:
        if user.pw_uid < 1000 and user.pw_name != "root":
            continue

        home = user.pw_dir

        if not home or not os.path.isdir(home):
            continue

        for rel_path in USER_INIT_FILES:
            full_path = os.path.join(
                home,
                rel_path,
            )

            if os.path.isfile(full_path):
                findings.extend(
                    _scan_file(full_path)
                )

            elif os.path.isdir(full_path):
                findings.extend(
                    _scan_dir(full_path)
                )

    findings.extend(
        _check_ld_preload()
    )

    findings.extend(
        _check_env_ld_preload()
    )

    return findings


def run_backdoor_check(
    silent: bool = False,
) -> dict:
    if get_os() != "Linux":
        if not silent:
            clear_screen()
            _header()

            console.print(
                Panel.fit(
                    "[yellow]Backdoor Detection is only supported on Linux.[/]",
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

    collected = scan_backdoors()

    findings = [
        item
        for item in collected
        if item["kind"] == "finding"
    ]

    errors = [
        item
        for item in collected
        if item["kind"] == "error"
    ]

    all_tags = {
        item["tag"]
        for item in findings
    }

    details = [
        f"{item['location']} — {item['reason']}"
        for item in findings
    ]

    if errors:
        details.extend(
            f"{item['location']} — {item['reason']}"
            for item in errors
        )

    if findings:
        status = "warning"
    elif errors:
        status = "error"
    else:
        status = "ok"

    result = {
        "status": status,
        "details": details[:10] if silent else details,
        "tags": sorted(all_tags),
    }

    if silent:
        return result

    clear_screen()
    _header()

    console.print(
        Panel.fit(
            f"[dim]Findings:[/] "
            f"[{'yellow' if findings else 'green'}]{len(findings)}[/]   "
            f"[dim]Errors:[/] "
            f"[{'yellow' if errors else 'green'}]{len(errors)}[/]",
            title="[bold cyan]SUMMARY[/]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )
    console.print()

    if findings:
        table = Table(
            title="[italic cyan]Persistence Findings[/]",
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
            show_edge=False,
            padding=(0, 1),
        )

        table.add_column(
            "Location",
            style="cyan",
            overflow="fold",
            min_width=24,
        )
        table.add_column(
            "Signal",
            style="yellow",
            overflow="fold",
        )
        table.add_column(
            "Content",
            style="dim",
            overflow="fold",
            max_width=70,
        )

        for finding in findings:
            table.add_row(
                finding["location"],
                finding["reason"],
                finding["line"] or "-",
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

        error_table.add_column(
            "Location",
            style="white",
        )
        error_table.add_column(
            "Issue",
            style="yellow",
        )

        for error in errors:
            error_table.add_row(
                error["location"],
                error["reason"],
            )

        console.print(error_table)
        console.print()

    if findings:
        console.print(
            Panel.fit(
                f"[yellow]{len(findings)} persistence indicator(s) require review.[/]\n"
                "[dim]Validate shell-init modifications, preload behavior, and whether the execution pattern is expected.[/]",
                title="[bold yellow]REVIEW REQUIRED[/]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )

    elif errors:
        console.print(
            Panel.fit(
                "[yellow]Backdoor inspection completed with collection errors.[/]\n"
                "[dim]Results may be incomplete; review permissions and inaccessible locations.[/]",
                title="[bold yellow]INCOMPLETE[/]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )

    else:
        console.print(
            Panel.fit(
                "[green]No backdoor or persistence indicators detected.[/]\n"
                "[dim]Shell initialization files and preload mechanisms did not match current detection rules.[/]",
                title="[bold green]STATUS: OK[/]",
                border_style="green",
                box=box.ROUNDED,
            )
        )

    pause_return()
    return result