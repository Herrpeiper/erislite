# /tools/suid_check.py
# Description: Scans the filesystem for SUID/SGID binaries and identifies potentially dangerous ones.
# This tool is designed to be run on Linux systems and will check for common SUID/SGID binaries as well as flag any that are found in unusual locations or have suspicious names.

import os, stat, json

from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.align import Align

from ui.utils import clear_screen, show_header, pause_return

console = Console()

# Common SUID/SGID binaries that are generally considered safe and are often required for normal system operation. These will be ignored in the scan results.
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

# Some SGID binaries are also commonly used and generally safe, but they can still be abused if misconfigured or if they have vulnerabilities. This list includes some of the more common ones that are typically not a concern.
WHITELISTED_SGID = {
    "/usr/bin/wall",
    "/usr/bin/write",
    "/usr/bin/locate",
    "/usr/bin/ssh-agent",
}

# The main function that performs the SUID/SGID scan. It walks through the filesystem, checks each file's permissions, and collects information about any files that have SUID or SGID bits set. It also applies some heuristics to identify potentially dangerous files based on their location and name.
def find_suid_sgid():
    flagged = []

    for root, dirs, files in os.walk("/", topdown=True):
        if root.startswith(("/proc", "/sys", "/dev")):
            continue

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

# This function runs the SUID/SGID scan and processes the results. It identifies any suspicious files based on their location and name, and then either returns a structured result for silent mode or displays an interactive report in the terminal.
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

