# Project: ErisLITE
# Module: integrity.py
# Author: Liam Piper-Brandon
# Version: 1.1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-02
# Description: SHA-256 file integrity baseline creation and change detection.

import glob
import hashlib
import json
import os
from datetime import datetime

from rich import box
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from erislite.config.settings import APP_NAME, APP_VERSION, INTEGRITY_BASELINE_FILE
from erislite.ui.console import console
from erislite.ui.utils import clear_screen, get_os, pause_return

BASELINE_PATH = INTEGRITY_BASELINE_FILE

MONITORED_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
]

SCAN_PROFILES = {
    "critical": MONITORED_FILES,
    "system": ["/etc/", "/usr/bin/", "/lib/", "/lib64/"],
    "user": [
        os.path.expanduser("~/.bashrc"),
        os.path.expanduser("~/.ssh/authorized_keys"),
        os.path.expanduser("~/.profile"),
    ],
}

def _header(title: str, subtitle: str) -> None:
    console.print(
        Panel(
            Text.from_markup(f"[dim]{subtitle}[/]"),
            title=f"[bold cyan]{title}[/]",
            subtitle=f"[dim cyan]{APP_NAME} v{APP_VERSION}[/]",
            border_style="cyan",
            box=box.SQUARE,
            padding=(0, 1),
        )
    )
    console.print()

def get_sha256(path: str):
    try:
        digest = hashlib.sha256()

        with open(path, "rb") as file:
            for chunk in iter(lambda: file.read(65536), b""):
                digest.update(chunk)

        return digest.hexdigest()

    except Exception:
        return None

def check_baseline_integrity() -> dict:
    if not os.path.exists(BASELINE_PATH):
        return {
            "status": "error",
            "details": ["Baseline file missing"],
            "tags": ["baseline_missing"],
        }

    try:
        with open(BASELINE_PATH, "r", encoding="utf-8") as file:
            data = json.load(file)

        metadata = data.get("_metadata", {})
        created_at = metadata.get("created_at")
        hashes = data.get("hashes")

        issues = []

        if not created_at:
            issues.append("Baseline creation metadata is missing")

        if not isinstance(hashes, dict):
            issues.append("Baseline hash data is malformed")
        monitored = metadata.get("monitored", [])
        unavailable = metadata.get("unavailable", [])

        if not hashes:
            issues.append("Baseline contains no readable file hashes")

        elif monitored and len(hashes) + len(unavailable) != len(monitored):
            issues.append(
                "Baseline contents do not match recorded monitored files"
            )

        return {
            "status": "warning" if issues else "ok",
            "details": issues,
            "tags": ["baseline_tamper"] if issues else [],
        }

    except Exception as e:
        return {
            "status": "error",
            "details": [
                f"Failed to validate baseline integrity: {e}"
            ],
            "tags": ["baseline_check_error"],
        }

def scan_for_copies(baseline: dict):
    shady_locations = [
        "/tmp",
        "/dev/shm",
        "/home",
        "/run",
        "/var/tmp",
    ]

    keywords = [
        "passwd",
        "shadow",
        "sudoers",
        "sshd_config",
        "hosts",
    ]

    flagged = []

    for root in shady_locations:
        if not os.path.exists(root):
            continue

        for keyword in keywords:
            pattern = os.path.join(
                root,
                "**",
                f"*{keyword}*",
            )

            for path in glob.glob(pattern, recursive=True):
                if not os.path.isfile(path):
                    continue

                copy_hash = get_sha256(path)

                for base_path, base_hash in baseline.items():
                    if (
                        keyword.lower() in base_path.lower()
                        and copy_hash
                        and copy_hash == base_hash
                    ):
                        flagged.append(
                            (path, "Exact copy of monitored file")
                        )
                        break

    return flagged

def create_baseline() -> None:
    clear_screen()
    _header(
        "FILE INTEGRITY",
        "Create a SHA-256 baseline for critical system files",
    )

    baseline = {}
    unavailable = []

    for path in MONITORED_FILES:
        hash_value = get_sha256(path)

        if hash_value:
            baseline[path] = hash_value
        else:
            unavailable.append(path)

    payload = {
        "_metadata": {
            "created_at": datetime.now().isoformat(),
            "algorithm": "SHA-256",
            "monitored": MONITORED_FILES,
            "unavailable": unavailable,
        },
        "hashes": baseline,
    }

    os.makedirs(
        os.path.dirname(BASELINE_PATH),
        exist_ok=True,
    )

    with open(
        BASELINE_PATH,
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(payload, file, indent=2)

    console.print(
        Panel.fit(
            f"[green]Baseline created successfully.[/]\n"
            f"[dim]Files Recorded:[/] [white]{len(baseline)}[/]   "
            f"[dim]Unavailable:[/] [white]{len(unavailable)}[/]\n"
            f"[dim]Path:[/] [white]{BASELINE_PATH}[/]",
            title="[bold green]BASELINE CREATED[/]",
            border_style="green",
            box=box.ROUNDED,
        )
    )

    if unavailable:
        console.print()

        table = Table(
            title="[italic cyan]Unavailable Files[/]",
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
            show_edge=False,
        )
        table.add_column("Path", style="white")

        for path in unavailable:
            table.add_row(path)

        console.print(table)

    pause_return()

def _collect_targets(profile: str) -> list[str]:
    targets = []

    for item in SCAN_PROFILES.get(profile, MONITORED_FILES):
        if os.path.isdir(item):
            for root, _, files in os.walk(item):
                for filename in files:
                    targets.append(
                        os.path.join(root, filename)
                    )

        elif os.path.isfile(item):
            targets.append(item)

    return targets

def scan_integrity(
    profile: str = "critical",
    silent: bool = False,
):
    if get_os() != "Linux":
        if not silent:
            clear_screen()
            _header(
                "FILE INTEGRITY",
                "Validate critical files against a known baseline",
            )

            console.print(
                Panel.fit(
                    "[yellow]File Integrity is only supported on Linux.[/]",
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

    if not os.path.exists(BASELINE_PATH):
        if not silent:
            clear_screen()
            _header(
                "FILE INTEGRITY",
                "Validate critical files against a known baseline",
            )

            console.print(
                Panel.fit(
                    "[yellow]No integrity baseline exists.[/]\n"
                    "[dim]Create a baseline before running an integrity scan.[/]",
                    title="[bold yellow]BASELINE REQUIRED[/]",
                    border_style="yellow",
                    box=box.ROUNDED,
                )
            )

            pause_return()

        return {
            "status": "error",
            "details": ["Baseline file missing"],
            "tags": ["file_integrity_issue"],
        }

    baseline_check = check_baseline_integrity()

    if baseline_check["status"] != "ok":
        if not silent:
            clear_screen()
            _header(
                "FILE INTEGRITY",
                "Validate critical files against a known baseline",
            )

            console.print(
                Panel.fit(
                    "\n".join(
                        f"[yellow]{detail}[/]"
                        for detail in baseline_check["details"]
                    ),
                    title="[bold yellow]BASELINE WARNING[/]",
                    border_style="yellow",
                    box=box.ROUNDED,
                )
            )

            pause_return()

        return baseline_check

    try:
        with open(
            BASELINE_PATH,
            "r",
            encoding="utf-8",
        ) as file:
            baseline = json.load(file).get("hashes", {})

    except Exception as e:
        return {
            "status": "error",
            "details": [f"Unable to load baseline: {e}"],
            "tags": ["file_integrity_issue"],
        }

    targets = _collect_targets(profile)

    if not targets:
        return {
            "status": "ok",
            "details": ["No files found for selected profile"],
            "tags": [],
        }

    rows = []
    issues = []

    for path in targets:
        old_hash = baseline.get(path)

        # Current baseline format only has hashes for files
        # that were included when the baseline was created.
        if old_hash is None:
            continue

        new_hash = get_sha256(path)

        if new_hash is None:
            rows.append((path, "MISSING"))
            issues.append(f"{path} is missing")

        elif new_hash != old_hash:
            rows.append((path, "MODIFIED"))
            issues.append(f"{path} was modified")

        else:
            rows.append((path, "UNCHANGED"))

    result = {
        "status": "warning" if issues else "ok",
        "details": issues,
        "tags": ["file_integrity_issue"] if issues else [],
    }

    if silent:
        return result

    clear_screen()
    _header(
        "FILE INTEGRITY SCAN",
        f"Validate files against the baseline • Profile: {profile.capitalize()}",
    )

    console.print(
        Panel.fit(
            f"[dim]Profile:[/] [white]{profile.capitalize()}[/]   "
            f"[dim]Checked:[/] [white]{len(rows)}[/]   "
            f"[dim]Issues:[/] "
            f"[{'yellow' if issues else 'green'}]{len(issues)}[/]",
            title="[bold cyan]SUMMARY[/]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )
    console.print()

    table = Table(
        title="[italic cyan]Integrity Results[/]",
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
        show_edge=False,
        padding=(0, 1),
    )
    table.add_column("File", style="white")
    table.add_column("Status", no_wrap=True)

    for path, status in rows:
        if status == "UNCHANGED":
            rendered = "[green]UNCHANGED[/]"
        elif status == "MODIFIED":
            rendered = "[yellow]MODIFIED[/]"
        else:
            rendered = "[red]MISSING[/]"

        table.add_row(path, rendered)

    console.print(table)
    console.print()

    copies = scan_for_copies(baseline)

    if copies:
        copy_table = Table(
            title="[italic cyan]Suspicious Copies[/]",
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
            show_edge=False,
            padding=(0, 1),
        )
        copy_table.add_column("Path", style="white")
        copy_table.add_column("Reason", style="yellow")

        for path, reason in copies:
            copy_table.add_row(path, reason)

        console.print(copy_table)
        console.print()

    if issues or copies:
        console.print(
            Panel.fit(
                f"[yellow]{len(issues)} integrity issue(s), "
                f"{len(copies)} suspicious copy finding(s).[/]\n"
                "[dim]Validate unexpected changes before restoring or replacing files.[/]",
                title="[bold yellow]REVIEW REQUIRED[/]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )
    else:
        console.print(
            Panel.fit(
                "[green]No file integrity issues detected.[/]\n"
                "[dim]Monitored files match the stored SHA-256 baseline.[/]",
                title="[bold green]STATUS: OK[/]",
                border_style="green",
                box=box.ROUNDED,
            )
        )

    pause_return()
    return result

def integrity_menu() -> None:
    while True:
        clear_screen()
        _header(
            "FILE INTEGRITY",
            "Create and validate SHA-256 baselines for critical files",
        )

        menu = Table(
            show_header=False,
            box=None,
            padding=(0, 1),
            collapse_padding=True,
        )
        menu.add_column(no_wrap=True)
        menu.add_column()
        menu.add_column()

        menu.add_row("[bold cyan]ACTIONS[/]", "", "")
        menu.add_row(
            "[cyan][1][/]",
            "Create Integrity Baseline",
            "[dim]Hash monitored critical files[/]",
        )
        menu.add_row(
            "[cyan][2][/]",
            "Run Integrity Scan",
            "[dim]Compare files against baseline[/]",
        )
        menu.add_row("", "", "")
        menu.add_row("[cyan][0][/]", "Back", "")

        console.print(menu)

        choice = Prompt.ask(
            "\n[cyan]Select an option[/]",
            choices=["0", "1", "2"],
            default="0",
        )

        if choice == "1":
            create_baseline()

        elif choice == "2":
            clear_screen()
            _header(
                "SELECT SCAN PROFILE",
                "Choose the scope for the integrity scan",
            )

            profiles = Table(
                show_header=False,
                box=None,
                padding=(0, 1),
            )
            profiles.add_row(
                "[cyan][1][/]",
                "Critical",
                "[dim]passwd, shadow, sudoers, SSH configuration[/]",
            )
            profiles.add_row(
                "[cyan][2][/]",
                "System",
                "[dim]/etc, /usr/bin, /lib[/]",
            )
            profiles.add_row(
                "[cyan][3][/]",
                "User",
                "[dim]Shell profile and authorized keys[/]",
            )
            profiles.add_row(
                "[cyan][0][/]",
                "Back",
                "",
            )

            console.print(profiles)

            selected = Prompt.ask(
                "\n[cyan]Select a profile[/]",
                choices=["0", "1", "2", "3"],
                default="1",
            )

            profile_map = {
                "1": "critical",
                "2": "system",
                "3": "user",
            }

            if selected in profile_map:
                scan_integrity(profile_map[selected])

        elif choice == "0":
            break