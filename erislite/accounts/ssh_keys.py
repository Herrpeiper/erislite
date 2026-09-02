# Project: ErisLITE
# Module: ssh_keys.py
# Author: Liam Piper-Brandon
# Version: 1.1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-02
# Description: SSH authorized_keys enumeration across user home directories.

import base64
import hashlib
import os
import pwd

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from erislite.config.settings import APP_NAME, APP_VERSION
from erislite.ui.console import console
from erislite.ui.utils import clear_screen, get_os, pause_return

KNOWN_KEY_TYPES = {
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
}


def _header() -> None:
    console.print(
        Panel(
            Text.from_markup(
                "[dim]Enumerate SSH authorized keys and review privileged account access[/]"
            ),
            title="[bold cyan]SSH KEY CHECK[/]",
            subtitle=f"[dim cyan]{APP_NAME} v{APP_VERSION}[/]",
            border_style="cyan",
            box=box.SQUARE,
            padding=(0, 1),
        )
    )
    console.print()


def _fingerprint(key_data: str) -> str:
    try:
        raw = base64.b64decode(key_data.encode())
        digest = hashlib.sha256(raw).digest()
        encoded = base64.b64encode(digest).decode().rstrip("=")
        return f"SHA256:{encoded[:20]}..."
    except Exception:
        return "Unavailable"


def _parse_key(line: str) -> dict:
    parts = line.split()

    key_type = "Unknown"
    key_data = ""
    comment = ""

    for index, part in enumerate(parts):
        if part in KNOWN_KEY_TYPES:
            key_type = part

            if len(parts) > index + 1:
                key_data = parts[index + 1]

            if len(parts) > index + 2:
                comment = " ".join(parts[index + 2:])

            break

    return {
        "key_type": key_type,
        "fingerprint": _fingerprint(key_data) if key_data else "Unavailable",
        "comment": comment or "-",
    }


def find_authorized_keys():
    entries = []

    for user in pwd.getpwall():
        if user.pw_uid < 1000 and user.pw_name != "root":
            continue

        home_dir = user.pw_dir

        if not home_dir or home_dir in ("/", "/dev/null"):
            continue

        auth_keys_path = os.path.join(
            home_dir,
            ".ssh",
            "authorized_keys",
        )

        if not os.path.isfile(auth_keys_path):
            continue

        try:
            with open(
                auth_keys_path,
                "r",
                encoding="utf-8",
                errors="ignore",
            ) as file:
                for lineno, raw_line in enumerate(file, 1):
                    line = raw_line.strip()

                    if not line or line.startswith("#"):
                        continue

                    parsed = _parse_key(line)

                    entries.append(
                        {
                            "user": user.pw_name,
                            "uid": user.pw_uid,
                            "path": auth_keys_path,
                            "line": lineno,
                            **parsed,
                        }
                    )

        except Exception:
            continue

    return entries


def _analyze_entry(entry: dict) -> tuple[list[str], set[str]]:
    reasons = []
    tags = set()

    if entry["user"] == "root":
        reasons.append("Root authorized key")
        tags.add("ssh_keys_user_root")

    elif entry["uid"] < 1000:
        reasons.append("System account authorized key")
        tags.add("ssh_keys_system_user")

    if entry["key_type"] == "Unknown":
        reasons.append("Unknown key format")
        tags.add("ssh_keys_unknown_type")

    return reasons, tags


def run_ssh_key_check(silent: bool = False):
    if get_os() != "Linux":
        if not silent:
            clear_screen()
            _header()

            console.print(
                Panel.fit(
                    "[yellow]SSH Key Check is only supported on Linux.[/]",
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

    entries = find_authorized_keys()

    findings = []
    tags = set()

    for entry in entries:
        reasons, local_tags = _analyze_entry(entry)

        if reasons:
            findings.append(
                {
                    **entry,
                    "reasons": reasons,
                }
            )

            tags.update(local_tags)

    users = {
        entry["user"]
        for entry in entries
    }

    details = []

    if findings:
        details.append(
            f"{len(findings)} SSH authorized key(s) require review"
        )

    result = {
        "status": "warning" if findings else "ok",
        "details": details,
        "tags": sorted(tags),
        "flagged": bool(findings),
        "key_count": len(entries),
        "user_count": len(users),
    }

    if silent:
        return result

    clear_screen()
    _header()

    console.print(
        Panel.fit(
            f"[dim]Keys:[/] [white]{len(entries)}[/]   "
            f"[dim]Users:[/] [white]{len(users)}[/]   "
            f"[dim]Review:[/] "
            f"[{'yellow' if findings else 'green'}]{len(findings)}[/]",
            title="[bold cyan]SUMMARY[/]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )
    console.print()

    if entries:
        table = Table(
            title="[italic cyan]Authorized SSH Keys[/]",
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
            show_edge=False,
            padding=(0, 1),
        )

        table.add_column(
            "User",
            style="cyan",
            no_wrap=True,
        )
        table.add_column(
            "Type",
            style="white",
            no_wrap=True,
        )
        table.add_column(
            "Fingerprint",
            style="white",
            no_wrap=True,
        )
        table.add_column(
            "Status",
            no_wrap=True,
        )
        table.add_column(
            "Comment",
            style="dim",
        )

        finding_paths = {
            (entry["path"], entry["line"])
            for entry in findings
        }

        for entry in entries:
            is_finding = (
                entry["path"],
                entry["line"],
            ) in finding_paths

            status = (
                "[yellow]REVIEW[/]"
                if is_finding
                else "[green]KNOWN[/]"
            )

            table.add_row(
                entry["user"],
                entry["key_type"],
                entry["fingerprint"],
                status,
                entry["comment"],
            )

        console.print(table)
        console.print()

    if findings:
        console.print(
            Panel.fit(
                f"[yellow]{len(findings)} SSH authorized key(s) require review.[/]\n"
                "[dim]Validate privileged-account keys, ownership, source, and whether access is expected.[/]",
                title="[bold yellow]REVIEW REQUIRED[/]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )

    elif entries:
        console.print(
            Panel.fit(
                "[green]No unusual SSH authorized-key placement detected.[/]\n"
                "[dim]Authorized keys were found only on expected user accounts.[/]",
                title="[bold green]STATUS: OK[/]",
                border_style="green",
                box=box.ROUNDED,
            )
        )

    else:
        console.print(
            Panel.fit(
                "[green]No SSH authorized keys were discovered.[/]\n"
                "[dim]No authorized_keys entries were present for enumerated accounts.[/]",
                title="[bold green]STATUS: OK[/]",
                border_style="green",
                box=box.ROUNDED,
            )
        )

    pause_return()
    return result