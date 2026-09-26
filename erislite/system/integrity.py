# Project: ErisLITE
# Module: integrity.py
# Author: Liam Piper-Brandon
# Version: 1.3.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-26
# Description: SHA-256 file integrity baseline creation and change detection.

import glob
import hashlib
import json
import os
from datetime import datetime
from typing import Optional, Tuple

from rich import box
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from erislite.config.settings import (
    APP_NAME,
    APP_VERSION,
    INTEGRITY_BASELINE_FILE,
)
from erislite.ui.console import console
from erislite.ui.utils import clear_screen, get_os, pause_return

def get_baseline_path(profile: str) -> str:
    base_dir = os.path.dirname(INTEGRITY_BASELINE_FILE)

    return os.path.join(
        base_dir,
        f"integrity_baseline_{profile}.json",
    )

MONITORED_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
]

SCAN_PROFILES = {
    "critical": MONITORED_FILES,

    "system": [
        "/etc/ssh/",
        "/etc/systemd/",
        "/etc/sudoers",
        "/etc/sudoers.d/",
        "/etc/pam.d/",
        "/etc/cron.d/",
        "/etc/cron.daily/",
        "/etc/cron.hourly/",
        "/etc/cron.weekly/",
        "/etc/cron.monthly/",
        "/etc/crontab",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/gshadow",
        "/etc/hosts",
        "/etc/resolv.conf",
        "/usr/bin/",
        "/usr/sbin/",
    ],

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

def get_sha256(path: str) -> Tuple[Optional[str], Optional[str]]:
    try:
        digest = hashlib.sha256()

        with open(path, "rb") as file:
            for chunk in iter(lambda: file.read(65536), b""):
                digest.update(chunk)

        return digest.hexdigest(), None

    except FileNotFoundError:
        return None, "missing"

    except PermissionError as exc:
        return None, f"permission denied: {exc}"

    except OSError as exc:
        return None, f"read failed: {exc}"

def check_baseline_integrity(profile: str = "critical") -> dict:
    baseline_path = get_baseline_path(profile)

    if not os.path.exists(baseline_path):
        return {
            "status": "error",
            "details": [
                f"{profile.capitalize()} baseline file missing"
            ],
            "tags": ["baseline_missing"],
        }

    try:
        with open(
            baseline_path,
            "r",
            encoding="utf-8",
        ) as file:
            data = json.load(file)

        metadata = data.get("_metadata", {})
        created_at = metadata.get("created_at")
        hashes = data.get("hashes")
        baseline_profile = metadata.get("profile")

        issues = []

        if not created_at:
            issues.append(
                "Baseline creation metadata is missing"
            )

        if not baseline_profile:
            issues.append(
                "Baseline profile metadata is missing"
            )
        elif baseline_profile not in SCAN_PROFILES:
            issues.append(
                f"Baseline profile is invalid: {baseline_profile}"
            )
        elif baseline_profile != profile:
            issues.append(
                f"Baseline profile '{baseline_profile}' does not match "
                f"expected profile '{profile}'"
            )

        if not isinstance(hashes, dict):
            issues.append(
                "Baseline hash data is malformed"
            )

        monitored = metadata.get("monitored", [])
        unavailable = metadata.get("unavailable", [])
        expected_absent = metadata.get("expected_absent", [])

        if not hashes:
            issues.append(
                "Baseline contains no readable file hashes"
            )

        elif monitored and (
            len(hashes)
            + len(unavailable)
            + len(expected_absent)
            != len(monitored)
        ):
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

                copy_hash, copy_error = get_sha256(path)

                if copy_error:
                    continue

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

def create_baseline(profile: str = "critical") -> None:
    baseline_path = get_baseline_path(profile)

    clear_screen()
    _header(
        "FILE INTEGRITY",
        f"Create a SHA-256 baseline • Profile: "
        f"{profile.capitalize()}",
    )

    targets, target_errors = _collect_targets(profile)

    baseline = {}
    unavailable = []
    expected_absent = []
    collection_errors = list(target_errors)

    for path in targets:
        hash_value, hash_error = get_sha256(path)

        if hash_value:
            baseline[path] = hash_value

        elif hash_error == "missing":
            expected_absent.append(path)

        else:
            unavailable.append(
                f"{path}: {hash_error or 'unavailable'}"
            )

    payload = {
        "_metadata": {
            "created_at": datetime.now().isoformat(),
            "algorithm": "SHA-256",
            "profile": profile,
            "monitored": targets,
            "expected_absent": expected_absent,
            "unavailable": unavailable,
            "collection_errors": collection_errors,
        },
        "hashes": baseline,
    }

    os.makedirs(
        os.path.dirname(baseline_path),
        exist_ok=True,
    )

    with open(
        baseline_path,
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(payload, file, indent=2)

    console.print(
        Panel.fit(
            f"[green]Baseline created successfully.[/]\n"
            f"[dim]Profile:[/] "
            f"[white]{profile.capitalize()}[/]   "
            f"[dim]Files Recorded:[/] "
            f"[white]{len(baseline)}[/]   "
            f"[dim]Unavailable:[/] "
            f"[white]{len(unavailable)}[/]\n"
            f"[dim]Path:[/] "
            f"[white]{baseline_path}[/]",
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
        table.add_column("Path / Error", style="white")

        for item in unavailable:
            table.add_row(str(item))

        console.print(table)

    pause_return()

def _collect_targets(profile: str) -> Tuple[list[str], list[str]]:
    targets = []
    errors = []

    def _walk_error(exc: OSError) -> None:
        errors.append(str(exc))

    for item in SCAN_PROFILES.get(profile, MONITORED_FILES):
        if os.path.isdir(item):
            for root, _, files in os.walk(
                item,
                onerror=_walk_error,
            ):
                for filename in files:
                    targets.append(
                        os.path.join(root, filename)
                    )

        elif item.endswith(os.sep):
            errors.append(
                f"Expected directory unavailable: {item}"
            )

        else:
            targets.append(item)

    return targets, errors

def scan_integrity(
    profile: str = "critical",
    silent: bool = False,
):
    if get_os() != "Linux":
        if not silent:
            clear_screen()
            _header(
                "FILE INTEGRITY",
                "Validate files against a known baseline",
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

    baseline_path = get_baseline_path(profile)

    if not os.path.exists(baseline_path):
        if not silent:
            clear_screen()
            _header(
                "FILE INTEGRITY",
                f"Validate files against the baseline • "
                f"Profile: {profile.capitalize()}",
            )

            console.print(
                Panel.fit(
                    f"[yellow]No {profile.capitalize()} "
                    f"integrity baseline exists.[/]\n"
                    f"[dim]Create a {profile.capitalize()} "
                    f"baseline before running this scan.[/]",
                    title="[bold yellow]BASELINE REQUIRED[/]",
                    border_style="yellow",
                    box=box.ROUNDED,
                )
            )

            pause_return()

        return {
            "status": "error",
            "details": [
                f"{profile.capitalize()} baseline file missing"
            ],
            "tags": ["baseline_missing"],
        }

    baseline_check = check_baseline_integrity(profile)

    if baseline_check["status"] != "ok":
        if not silent:
            clear_screen()
            _header(
                "FILE INTEGRITY",
                f"Validate files against the baseline • "
                f"Profile: {profile.capitalize()}",
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
            baseline_path,
            "r",
            encoding="utf-8",
        ) as file:
            baseline_data = json.load(file)

        baseline = baseline_data.get("hashes", {})
        metadata = baseline_data.get("_metadata", {})
        expected_absent = set(
            metadata.get("expected_absent", [])
        )

    except Exception as e:
        return {
            "status": "error",
            "details": [
                f"Unable to load baseline: {e}"
            ],
            "tags": ["file_integrity_issue"],
        }

    targets, target_errors = _collect_targets(profile)

    if not targets:
        if target_errors:
            return {
                "status": "error",
                "details": [
                    f"Integrity target collection incomplete: {error}"
                    for error in target_errors
                ],
                "tags": ["integrity_scan_incomplete"],
            }

        return {
            "status": "ok",
            "details": [
                "No files found for selected profile"
            ],
            "tags": [],
        }

    rows = []
    issues = []
    scan_errors = list(target_errors)

    for path in targets:
        if path in expected_absent:
            if not os.path.lexists(path):
                rows.append((path, "ABSENT"))
                continue

            if os.path.islink(path) and not os.path.exists(path):
                rows.append((path, "BROKEN LINK"))
                issues.append(
                    f"{path} appeared after baseline creation "
                    "as a broken symbolic link"
                )
                continue

            new_hash, hash_error = get_sha256(path)

            if hash_error:
                rows.append((path, "UNAVAILABLE"))
                scan_errors.append(
                    f"{path} appeared after baseline creation "
                    f"but could not be inspected: {hash_error}"
                )
            else:
                rows.append((path, "CREATED"))
                issues.append(
                    f"{path} appeared but was absent when "
                    "the baseline was created"
                )

            continue

        old_hash = baseline.get(path)

        if old_hash is None:
            if os.path.islink(path) and not os.path.exists(path):
                rows.append((path, "UNAVAILABLE"))
                scan_errors.append(
                    f"{path} is a broken symbolic link"
                )
            else:
                rows.append((path, "UNAVAILABLE"))
                scan_errors.append(
                    f"{path} is not represented in the active baseline"
                )

            continue

        new_hash, hash_error = get_sha256(path)

        if hash_error == "missing":
            rows.append((path, "MISSING"))
            issues.append(
                f"{path} is missing"
            )

        elif hash_error:
            rows.append((path, "UNAVAILABLE"))
            scan_errors.append(
                f"{path} could not be inspected: {hash_error}"
            )

        elif new_hash != old_hash:
            rows.append((path, "MODIFIED"))
            issues.append(
                f"{path} was modified"
            )

        else:
            rows.append((path, "UNCHANGED"))

    tags = []

    if issues:
        tags.append("file_integrity_issue")

    if scan_errors:
        tags.append("integrity_scan_incomplete")

    if issues:
        status = "warning"
    elif scan_errors:
        status = "error"
    else:
        status = "ok"

    result = {
        "status": status,
        "details": issues
        + [
            f"Integrity inspection incomplete: {error}"
            for error in scan_errors
        ],
        "tags": tags,
    }

    if silent:
        return result

    clear_screen()
    _header(
        "FILE INTEGRITY SCAN",
        f"Validate files against the baseline • "
        f"Profile: {profile.capitalize()}",
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

    for path, row_status in rows:
        if row_status == "UNCHANGED":
            rendered = "[green]UNCHANGED[/]"

        elif row_status == "ABSENT":
            rendered = "[green]ABSENT[/]"

        elif row_status == "MODIFIED":
            rendered = "[yellow]MODIFIED[/]"

        elif row_status == "CREATED":
            rendered = "[yellow]CREATED[/]"

        elif row_status == "MISSING":
            rendered = "[red]MISSING[/]"

        elif row_status == "BROKEN LINK":
            rendered = "[yellow]BROKEN LINK[/]"

        else:
            rendered = "[yellow]UNAVAILABLE[/]"

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

    if scan_errors and (issues or copies):
        details = "\n".join(
            f"[yellow]• {error}[/]"
            for error in scan_errors[:10]
        )

        if len(scan_errors) > 10:
            details += (
                f"\n[dim]...and {len(scan_errors) - 10} "
                "additional inspection error(s).[/]"
            )

        console.print(
            Panel.fit(
                details,
                title="[bold yellow]COLLECTION WARNING[/]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )
        console.print()

    if issues or copies:
        console.print(
            Panel.fit(
                f"[yellow]{len(issues)} integrity issue(s), "
                f"{len(copies)} suspicious copy finding(s).[/]\n"
                "[dim]Validate unexpected changes before restoring "
                "or replacing files.[/]",
                title="[bold yellow]REVIEW REQUIRED[/]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )

    elif scan_errors:
        details = "\n".join(
            f"[yellow]• {error}[/]"
            for error in scan_errors[:10]
        )

        if len(scan_errors) > 10:
            details += (
                f"\n[dim]...and {len(scan_errors) - 10} "
                "additional inspection error(s).[/]"
            )

        console.print(
            Panel.fit(
                "[yellow]No integrity changes were detected, "
                "but the scan was incomplete.[/]\n\n"
                + details,
                title="[bold yellow]STATUS: INCOMPLETE[/]",
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
            "Create and validate SHA-256 baselines",
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
            "[dim]Create a profile-specific baseline[/]",
        )
        menu.add_row(
            "[cyan][2][/]",
            "Run Integrity Scan",
            "[dim]Compare files against the matching baseline[/]",
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
            clear_screen()
            _header(
                "SELECT BASELINE PROFILE",
                "Choose the scope for the integrity baseline",
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
                "[dim]Security configs, persistence paths, "
                "and system binaries[/]",
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
                create_baseline(profile_map[selected])

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
                "[dim]Security configs, persistence paths, "
                "and system binaries[/]",
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