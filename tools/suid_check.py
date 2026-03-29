# Project: ErisLITE
# Module: suid_check.py
# Author: Liam Piper-Brandon
# Version: 0.6
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-03-29
# Description:
#   Scans the filesystem for SUID/SGID binaries and identifies potentially dangerous ones.
#   Designed for Linux systems. Skips virtual, noisy, and container-managed paths to avoid
#   hangs and false positives — exclusion list now matches world_writable_check.py.

import os, stat, json

from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.align import Align

from ui.utils import clear_screen, show_header, pause_return

console = Console()

# Paths to skip entirely during the filesystem walk.
# Matches the exclusion set used in world_writable_check.py for consistency.
SKIP_PREFIXES = (
    "/proc", "/sys", "/dev", "/run",
    "/snap", "/var/lib/docker", "/var/lib/snapd",
)

# Common SUID binaries that are generally considered safe and required for normal system operation.
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
    "/bin/ping",
    "/bin/ping6",
}

# Common SGID binaries that are generally considered safe.
WHITELISTED_SGID = {
    "/usr/bin/wall",
    "/usr/bin/write",
    "/usr/bin/locate",
    "/usr/bin/ssh-agent",
}


def find_suid_sgid():
    flagged = []

    for root, dirs, files in os.walk("/", topdown=True):
        # Prune virtual/noisy directory trees in-place so os.walk won't descend into them
        if root.startswith(SKIP_PREFIXES):
            dirs[:] = []
            continue

        # Also prune any subdirectory that starts with a skip prefix
        dirs[:] = [
            d for d in dirs
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
                    flagged.append({
                        "path": path,
                        "suid": is_suid,
                        "sgid": is_sgid
                    })

            except Exception:
                continue

    return flagged


def run_suid_scan(silent=False):
    results = find_suid_sgid()
    suspicious = []
    tags = set()

    interpreters = {"python", "perl", "ruby", "bash", "sh", "dash", "zsh"}

    for f in results:
        path = f["path"]
        is_known = (
            (f["suid"] and path in WHITELISTED_SUID) or
            (f["sgid"] and path in WHITELISTED_SGID)
        )

        if not is_known:
            tag_local = {"suid_sgid"}

            if any(path.startswith(p) for p in ["/tmp", "/var/tmp", "/dev/shm", "/home"]):
                tag_local.add("suid_dangerous_path")

            if not path.startswith(("/bin", "/usr/bin", "/sbin", "/usr/sbin")):
                tag_local.add("suid_nonstandard_location")

            if any(interpreter in os.path.basename(path).lower() for interpreter in interpreters):
                tag_local.add("suid_interpreter")

            suspicious.append(f)
            tags.update(tag_local)

    if silent:
        return {
            "status": "warning" if suspicious else "ok",
            "details": [f"{len(suspicious)} suspicious SUID/SGID binaries found"] if suspicious else [],
            "tags": sorted(list(tags)) if tags else []
        }

    # Interactive output
    clear_screen()
    show_header("SUID / SGID CHECK")

    if not results:
        console.print("[green]No SUID or SGID files found (unexpected).[/]")
        pause_return()
        return {
            "status": "ok",
            "details": [],
            "tags": []
        }

    table = Table(title="Detected SUID / SGID Files", show_lines=True)
    table.add_column("Path", style="magenta")
    table.add_column("Flags", style="cyan")
    table.add_column("Status", style="yellow")

    for entry in results:
        flags = []
        if entry["suid"]:
            flags.append("SUID")
        if entry["sgid"]:
            flags.append("SGID")

        path = entry["path"]
        is_known = (
            (entry["suid"] and path in WHITELISTED_SUID) or
            (entry["sgid"] and path in WHITELISTED_SGID)
        )

        status = "[green]Known Safe[/]" if is_known else "[red]Suspicious[/]"
        table.add_row(path, ", ".join(flags), status)

    console.print(Align.center(table))

    if suspicious:
        console.print(f"\n[bold red]⚠️ {len(suspicious)} suspicious SUID/SGID binaries detected.[/]")
    else:
        console.print("\n[green]✅ No unexpected SUID/SGID binaries detected.[/]")

    pause_return()

    return {
        "status": "warning" if suspicious else "ok",
        "details": [f"{len(suspicious)} suspicious SUID/SGID binaries found"] if suspicious else [],
        "tags": sorted(list(tags)) if tags else []
    }
