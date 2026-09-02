# Project: ErisLITE
# Module: suid.py
# Author: Liam Piper-Brandon
# Version: 1.1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-02
# Description: SUID/SGID binary scan for unexpected privileged executables.

import os
import stat
from typing import Dict, List

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from erislite.config.settings import APP_NAME, APP_VERSION
from erislite.ui.console import console
from erislite.ui.utils import clear_screen, get_os, pause_return

SKIP_PREFIXES = (
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/snap",
    "/var/lib/docker",
    "/var/lib/snapd",
)

WHITELISTED_SUID = {
    "/usr/bin/su",
    "/usr/bin/passwd",
    "/usr/bin/sudo",
    "/usr/bin/chsh",
    "/usr/bin/chfn",
    "/usr/bin/newgrp",
    "/usr/bin/gpasswd",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/bin/crontab",
    "/usr/bin/ssh-agent",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/lib/polkit-1/polkit-agent-helper-1",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/bin/ping",
    "/bin/ping6",
}

WHITELISTED_SGID = {
    "/usr/bin/wall",
    "/usr/bin/write",
    "/usr/bin/locate",
    "/usr/bin/ssh-agent",
    "/usr/sbin/pam_extrausers_chkpwd",
    "/usr/sbin/unix_chkpwd",
    "/usr/bin/chage",
    "/usr/bin/expiry",
}

INTERPRETERS = {
    "python",
    "python3",
    "perl",
    "ruby",
    "bash",
    "sh",
    "dash",
    "zsh",
}

DANGEROUS_PATHS = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/home/",
)

STANDARD_EXEC_PATHS = (
    "/bin/",
    "/usr/bin/",
    "/sbin/",
    "/usr/sbin/",
)


def _header() -> None:
    console.print(
        Panel(
            Text.from_markup(
                "[dim]Inspect privileged executables for unexpected SUID and SGID permissions[/]"
            ),
            title="[bold cyan]SUID / SGID CHECK[/]",
            subtitle=f"[dim cyan]{APP_NAME} v{APP_VERSION}[/]",
            border_style="cyan",
            box=box.SQUARE,
            padding=(0, 1),
        )
    )
    console.print()


def find_suid_sgid() -> List[Dict]:
    flagged = []

    for root, dirs, files in os.walk("/", topdown=True, followlinks=False):
        if root.startswith(SKIP_PREFIXES):
            dirs[:] = []
            continue

        dirs[:] = [
            d
            for d in dirs
            if not os.path.join(root, d).startswith(SKIP_PREFIXES)
        ]

        for name in files:
            path = os.path.join(root, name)

            if os.path.islink(path):
                continue

            try:
                st = os.lstat(path)
                mode = st.st_mode

                is_suid = bool(mode & stat.S_ISUID)
                is_sgid = bool(mode & stat.S_ISGID)

                if is_suid or is_sgid:
                    flagged.append(
                        {
                            "path": path,
                            "suid": is_suid,
                            "sgid": is_sgid,
                        }
                    )

            except (FileNotFoundError, PermissionError):
                continue

            except Exception:
                continue

    return flagged


def _is_known(entry: Dict) -> bool:
    path = entry["path"]

    suid_known = (
        entry["suid"]
        and path in WHITELISTED_SUID
    )

    sgid_known = (
        entry["sgid"]
        and path in WHITELISTED_SGID
    )

    if entry["suid"] and entry["sgid"]:
        return suid_known and sgid_known

    return suid_known or sgid_known


def _analyze_entry(entry: Dict) -> tuple[list[str], set[str]]:
    path = entry["path"]

    reasons = []
    tags = {"suid_sgid"}

    if path.startswith(DANGEROUS_PATHS):
        reasons.append("Dangerous path")
        tags.add("suid_dangerous_path")

    if not path.startswith(STANDARD_EXEC_PATHS):
        reasons.append("Non-standard location")
        tags.add("suid_nonstandard_location")

    basename = os.path.basename(path).lower()

    if basename in INTERPRETERS:
        reasons.append("Privileged interpreter")
        tags.add("suid_interpreter")

    if not reasons:
        reasons.append("Not in known-safe baseline")

    return reasons, tags


def run_suid_scan(silent: bool = False):
    if get_os() != "Linux":
        if not silent:
            clear_screen()
            _header()

            console.print(
                Panel.fit(
                    "[yellow]SUID / SGID Check is only supported on Linux.[/]",
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

    results = find_suid_sgid()

    suspicious = []
    tags = set()

    for entry in results:
        if _is_known(entry):
            continue

        reasons, local_tags = _analyze_entry(entry)

        suspicious.append(
            {
                **entry,
                "reasons": reasons,
            }
        )

        tags.update(local_tags)

    details = (
        [
            f"{len(suspicious)} suspicious SUID/SGID binary(s) found"
        ]
        if suspicious
        else []
    )

    result = {
        "status": "warning" if suspicious else "ok",
        "details": details,
        "tags": sorted(tags),
    }

    if silent:
        return result

    clear_screen()
    _header()

    console.print(
        Panel.fit(
            f"[dim]Detected:[/] [white]{len(results)}[/]   "
            f"[dim]Known:[/] [green]{len(results) - len(suspicious)}[/]   "
            f"[dim]Review:[/] "
            f"[{'yellow' if suspicious else 'green'}]{len(suspicious)}[/]",
            title="[bold cyan]SUMMARY[/]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )
    console.print()

    if not results:
        console.print(
            Panel.fit(
                "[yellow]No SUID or SGID files were detected.[/]\n"
                "[dim]This may be valid in a minimal environment, but is unusual on many Linux systems.[/]",
                title="[bold yellow]NO RESULTS[/]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )

        pause_return()
        return result

    table = Table(
        title="[italic cyan]Privileged Executables[/]",
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
        show_edge=False,
        padding=(0, 1),
    )

    table.add_column("Path", style="white")
    table.add_column("Flags", style="cyan", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Reason", style="dim")

    suspicious_map = {
        entry["path"]: entry
        for entry in suspicious
    }

    for entry in results:
        flags = []

        if entry["suid"]:
            flags.append("SUID")

        if entry["sgid"]:
            flags.append("SGID")

        path = entry["path"]

        if path in suspicious_map:
            status = "[yellow]REVIEW[/]"
            reason = ", ".join(
                suspicious_map[path]["reasons"]
            )
        else:
            status = "[green]KNOWN[/]"
            reason = "Known-safe baseline"

        table.add_row(
            path,
            ", ".join(flags),
            status,
            reason,
        )

    console.print(table)
    console.print()

    if suspicious:
        console.print(
            Panel.fit(
                f"[yellow]{len(suspicious)} privileged executable(s) require review.[/]\n"
                "[dim]Validate ownership, package origin, location, and whether elevated execution is expected.[/]",
                title="[bold yellow]REVIEW REQUIRED[/]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )

    else:
        console.print(
            Panel.fit(
                "[green]No unexpected SUID/SGID binaries detected.[/]\n"
                "[dim]All detected privileged executables matched the current known-safe baseline.[/]",
                title="[bold green]STATUS: OK[/]",
                border_style="green",
                box=box.ROUNDED,
            )
        )

    pause_return()
    return result