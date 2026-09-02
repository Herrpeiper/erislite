# Project: ErisLITE
# Module: world_writable.py
# Author: Liam Piper-Brandon
# Version: 1.1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-02
# Description: World-writable file and directory inspection in critical filesystem paths.

import os, stat
from typing import Dict, List, Set

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from erislite.config.settings import APP_NAME, APP_VERSION
from erislite.ui.console import console
from erislite.ui.utils import clear_screen, get_os, pause_return

# Things we should basically never traverse for this check (noise / virtual FS / huge)
SKIP_PREFIXES = (
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/snap",
    "/var/lib/docker",
    "/var/lib/snapd",
)

# For filtered mode (used by Threat Sweep): focus on places that matter for persistence/execution
CRITICAL_ROOTS = (
    "/etc",
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/etc/systemd",
    "/lib/systemd",
    "/usr/lib/systemd",
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/var/www",
)

# Risky file extensions (only meaningful in the right directories)
RISKY_EXTENSIONS = (
    ".sh",
    ".py",
    ".pl",
    ".rb",
    ".php",
    ".conf",
    ".service",
    ".socket",
    ".timer",
)

# If you want a small preview list for logs, cap it
MAX_PREVIEW = 50

def _header(full_scan: bool = False) -> None:
    mode = "Full Filesystem" if full_scan else "Critical Paths"

    console.print(
        Panel(
            Text.from_markup(
                f"[dim]Review world-writable files and directories • Scope: {mode}[/]"
            ),
            title="[bold cyan]WORLD-WRITABLE CHECK[/]",
            subtitle=f"[dim cyan]{APP_NAME} v{APP_VERSION}[/]",
            border_style="cyan",
            box=box.SQUARE,
            padding=(0, 1),
        )
    )
    console.print()

def _should_skip(path: str) -> bool:
    return path.startswith(SKIP_PREFIXES)


def _is_world_writable(mode: int) -> bool:
    return bool(mode & stat.S_IWOTH)


def _is_executable(mode: int) -> bool:
    return bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))


def _is_risky_file(path: str) -> bool:
    return path.endswith(RISKY_EXTENSIONS)


def _walk_roots(roots: List[str]) -> Set[str]:
    """
    Walk selected roots and return a set of high-signal world-writable paths.
    """
    suspicious: Set[str] = set()

    for base in roots:
        if not os.path.exists(base):
            continue

        for root, dirs, files in os.walk(base, topdown=True, followlinks=False):
            if _should_skip(root):
                dirs[:] = []
                continue

            # prune common noisy dirs if present
            dirs[:] = [d for d in dirs if d not in {".git", ".cache"}]

            for name in dirs + files:
                path = os.path.join(root, name)

                # skip symlinks
                if os.path.islink(path):
                    continue

                try:
                    st = os.lstat(path)
                    mode = st.st_mode

                    if not _is_world_writable(mode):
                        continue

                    is_dir = stat.S_ISDIR(mode)
                    is_reg = stat.S_ISREG(mode)
                    is_exec = _is_executable(mode)

                    # Filter rules (high signal):
                    # - Any world-writable directory inside CRITICAL_ROOTS is suspicious (drop location)
                    # - Any world-writable executable file is suspicious
                    # - Any world-writable risky-extension file in CRITICAL_ROOTS is suspicious
                    if is_dir:
                        suspicious.add(path)
                    elif is_reg:
                        if is_exec:
                            suspicious.add(path)
                        elif _is_risky_file(path):
                            suspicious.add(path)

                except (FileNotFoundError, PermissionError):
                    continue
                except Exception:
                    continue

    return suspicious


def _walk_full_filesystem() -> Set[str]:
    """
    Full/raw mode: walk / (still skipping virtual/noisy trees),
    returning all world-writable dirs + risky-type files.
    Use for manual inspection only.
    """
    suspicious: Set[str] = set()

    for root, dirs, files in os.walk("/", topdown=True, followlinks=False):
        if _should_skip(root):
            dirs[:] = []
            continue

        # prune safe/noise-ish user run dirs etc.
        dirs[:] = [d for d in dirs if d not in {".git", ".cache"}]

        for name in dirs + files:
            path = os.path.join(root, name)

            if os.path.islink(path):
                continue

            try:
                st = os.lstat(path)
                mode = st.st_mode

                if not _is_world_writable(mode):
                    continue

                is_dir = stat.S_ISDIR(mode)
                is_reg = stat.S_ISREG(mode)

                # In full mode we still avoid listing every single random file:
                # keep dirs and "risky-ish" files.
                if is_dir:
                    suspicious.add(path)
                elif is_reg and (_is_executable(mode) or _is_risky_file(path)):
                    suspicious.add(path)

            except (FileNotFoundError, PermissionError):
                continue
            except Exception:
                continue

    return suspicious


def run_world_writable_check(silent: bool = False, filter_by_type: bool = True, full_scan: bool = False) -> Dict:
    os_type = get_os()

    if os_type != "Linux":
        if not silent:
            clear_screen()
            _header(full_scan)

            console.print(
                Panel.fit("[yellow]World-Writable Check is only supported on Linux.[/]", border_style="yellow", box=box.ROUNDED, )
            )

            pause_return()

        return {
            "status": "unsupported",
            "details": [],
            "tags": [],
        }

    # Decide scan scope
    if full_scan:
        suspicious = _walk_full_filesystem()
    else:
        suspicious = _walk_roots(list(CRITICAL_ROOTS))

    # Optionally keep the old "filter_by_type" behavior:
    # If filter_by_type=False, include all world-writable regular files in critical roots too (noisy).
    if not filter_by_type and not full_scan:
        # expand to include all world-writable files under critical roots (not recommended for sweep)
        expanded: Set[str] = set(suspicious)
        for base in CRITICAL_ROOTS:
            if not os.path.exists(base):
                continue
            for root, dirs, files in os.walk(base, topdown=True, followlinks=False):
                if _should_skip(root):
                    dirs[:] = []
                    continue
                for name in files:
                    path = os.path.join(root, name)
                    if os.path.islink(path):
                        continue
                    try:
                        st = os.lstat(path)
                        if stat.S_ISREG(st.st_mode) and _is_world_writable(st.st_mode):
                            expanded.add(path)
                    except Exception:
                        continue
        suspicious = expanded

    # UI output
    if not silent:
        clear_screen()
        _header(full_scan)

        scope = "Full Filesystem" if full_scan else "Critical Paths"

        console.print(
            Panel.fit(
                f"[dim]Scope:[/] [white]{scope}[/]   "
                f"[dim]Findings:[/] "
                f"[{'yellow' if suspicious else 'green'}]{len(suspicious)}[/]",
                title="[bold cyan]SUMMARY[/]",
                border_style="cyan",
                box=box.ROUNDED,
            )
        )
        console.print()

        if suspicious:
            table = Table(
                title="[italic cyan]World-Writable Findings[/]",
                box=box.SIMPLE_HEAVY,
                header_style="bold cyan",
                show_edge=False,
                padding=(0, 1),
            )

            table.add_column("Path", style="white")
            table.add_column("Type", style="cyan", no_wrap=True)
            table.add_column("Risk", no_wrap=True)

            for item in sorted(suspicious):
                try:
                    mode = os.lstat(item).st_mode
                    is_dir = stat.S_ISDIR(mode)
                    is_exec = _is_executable(mode)

                    if is_dir:
                        item_type = "Directory"
                        risk = "[yellow]DROP LOCATION[/]"
                    else:
                        item_type = "File"
                        risk = (
                            "[red]EXECUTABLE[/]"
                            if is_exec
                            else "[yellow]WRITABLE FILE[/]"
                        )

                    table.add_row(
                        item,
                        item_type,
                        risk,
                    )

                except Exception:
                    continue

            console.print(table)
            console.print()

            console.print(
                Panel.fit(
                    f"[yellow]{len(suspicious)} world-writable item(s) require review.[/]\n"
                    "[dim]Validate writable directories, executable files, and configuration "
                    "files in privileged or persistence-sensitive locations.[/]",
                    title="[bold yellow]REVIEW REQUIRED[/]",
                    border_style="yellow",
                    box=box.ROUNDED,
                )
            )

        else:
            console.print(
                Panel.fit(
                    "[green]No high-signal world-writable items detected.[/]\n"
                    "[dim]No writable execution or persistence paths matched the current scan scope.[/]",
                    title="[bold green]STATUS: OK[/]",
                    border_style="green",
                    box=box.ROUNDED,
                )
            )

        pause_return()

    if suspicious:
        preview = sorted(suspicious)[:MAX_PREVIEW]

        return {
            "status": "warning",
            "details": [
                f"{len(suspicious)} high-signal world-writable item(s) found "
                f"({'full filesystem' if full_scan else 'critical paths'})"
            ],
            "tags": ["world_writable"],
            "preview": preview,
        }

    return {
        "status": "ok",
        "details": [],
        "tags": [],
    }