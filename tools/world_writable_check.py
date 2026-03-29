# tools/world_writable_check.py

import os
import stat
from typing import List, Set, Dict

from rich.console import Console
from rich.table import Table

from ui.utils import clear_screen, show_header, pause_return, get_os

console = Console()

# Things we should basically never traverse for this check (noise / virtual FS / huge)
SKIP_PREFIXES = (
    "/proc", "/sys", "/dev", "/run", "/snap",
    "/var/lib/docker", "/var/lib/snapd",
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
    "/opt",          # optional: keep or remove depending on your environment
    "/var/www",      # optional: webroots often matter
)

# Risky file extensions (only meaningful in the right directories)
RISKY_EXTENSIONS = (".sh", ".py", ".pl", ".rb", ".php", ".conf", ".service", ".socket", ".timer")

# If you want a small preview list for logs, cap it
MAX_PREVIEW = 50


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
            show_header("WORLD-WRITABLE CHECK")
            console.print("[yellow]This module is only supported on Linux.[/]")
            pause_return()
        return {"status": "unsupported", "details": [], "tags": []}

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
        show_header("WORLD-WRITABLE CHECK" + (" (FULL)" if full_scan else " (FILTERED)"))

        if suspicious:
            table = Table(title="World-Writable (High-Signal)", show_lines=True)
            table.add_column("Path", style="magenta")
            table.add_column("Type", style="cyan")

            for item in sorted(suspicious):
                try:
                    mode = os.lstat(item).st_mode
                    item_type = "Directory" if stat.S_ISDIR(mode) else "File"
                    table.add_row(item, item_type)
                except Exception:
                    continue

            console.print(table)
        else:
            console.print("[green]✔ No high-signal world-writable items detected.[/]")

        pause_return()

    # Return structured results (good for Threat Sweep)
    if suspicious:
        preview = sorted(list(suspicious))[:MAX_PREVIEW]
        return {
            "status": "warning",
            "details": [f"{len(suspicious)} world-writable item(s) found ({'full' if full_scan else 'filtered'})"],
            "tags": ["world_writable"],
            "preview": preview,  # optional, ignore if you don't want it
        }

    return {"status": "ok", "details": [], "tags": []}
