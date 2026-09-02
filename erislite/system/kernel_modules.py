# Project: ErisLITE
# Module: kernel_modules.py
# Author: Liam Piper-Brandon
# Version: 1.1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-02
# Description: Kernel module inspection for known-bad names, untracked modules, and unusual paths.

import json
import os
import shutil
import subprocess
from datetime import datetime

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from erislite.config.settings import APP_NAME, APP_VERSION
from erislite.ui.console import console
from erislite.ui.utils import clear_screen, get_os, pause_return

KNOWN_BAD_MODULES = {
    "adore",
    "diamorphine",
    "suterusu",
    "rootkit",
    "hideproc",
    "hideme",
    "kbeast",
    "reptile",
    "mushroom",
}

def _header() -> None:
    console.print(
        Panel(
            Text.from_markup(
                "[dim]Inspect loaded kernel modules for integrity and path anomalies[/]"
            ),
            title="[bold cyan]KERNEL MODULE CHECK[/]",
            subtitle=f"[dim cyan]{APP_NAME} v{APP_VERSION}[/]",
            border_style="cyan",
            box=box.SQUARE,
            padding=(0, 1),
        )
    )
    console.print()

def _kernel_release() -> str:
    try:
        result = subprocess.run(
            ["uname", "-r"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.strip() if result.returncode == 0 else ""
    except Exception:
        return ""

def get_module_path(modname: str) -> str:
    try:
        result = subprocess.run(
            ["modinfo", "-n", modname],
            capture_output=True,
            text=True,
            timeout=5,
        )

        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()

    except Exception:
        pass

    return "Unknown"

def get_loaded_modules():
    if shutil.which("lsmod") is None:
        return [], "lsmod is not available on this system"

    try:
        result = subprocess.run(
            ["lsmod"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode != 0:
            return [], (
                result.stderr.strip()
                or f"lsmod exited with code {result.returncode}"
            )

        lines = result.stdout.strip().splitlines()

        if len(lines) <= 1:
            return [], None

        modules = []

        for line in lines[1:]:
            parts = line.split()

            if len(parts) >= 3:
                modules.append(
                    (parts[0], parts[1], parts[2])
                )

        return modules, None

    except subprocess.TimeoutExpired:
        return [], "lsmod timed out"

    except Exception as exc:
        return [], str(exc)

def _status_text(flags) -> str:
    if "KnownBadName" in flags:
        return "[red]CRITICAL[/]"

    if "Rogue/Untracked" in flags:
        return "[red]WARNING[/]"

    if "UnusualPath" in flags:
        return "[yellow]WARNING[/]"

    if "Unused" in flags:
        return "[dim]INFO[/]"

    return "[green]OK[/]"

def run_kernel_module_check(
    silent: bool = False,
    profile: str = "default",
):
    if get_os() != "Linux":
        if not silent:
            clear_screen()
            _header()

            console.print(
                Panel.fit(
                    "[yellow]Kernel Module Check is only supported on Linux.[/]",
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

    krel = _kernel_release()
    expected_prefix = (
        f"/lib/modules/{krel}/"
        if krel
        else "/lib/modules/"
    )

    modules, collection_error = get_loaded_modules()

    if collection_error:
        result = {
            "status": "unsupported",
            "details": [collection_error],
            "tags": [],
        }

        if silent:
            return result

        clear_screen()
        _header()

        console.print(
            Panel.fit(
                f"[yellow]Kernel module inspection is unavailable.[/]\n"
                f"[dim]{collection_error}[/]",
                title="[bold yellow]UNAVAILABLE[/]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )

        pause_return()
        return result

    bad_named = []
    rogue = []
    path_flags = []
    info_unused = []
    module_log = []

    for name, size, used_by in modules:
        path = get_module_path(name)
        flags = []

        if name.lower() in KNOWN_BAD_MODULES:
            flags.append("KnownBadName")
            bad_named.append(name)

        is_legit = (
            path != "Unknown"
            and path.startswith(expected_prefix)
        )

        if not is_legit:
            flags.append("Rogue/Untracked")
            rogue.append(name)

            if (
                path != "Unknown"
                and not path.startswith(expected_prefix)
            ):
                flags.append("UnusualPath")
                path_flags.append((name, path))

        elif used_by == "0":
            flags.append("Unused")
            info_unused.append(name)

        module_log.append({
            "name": name,
            "size": size,
            "used_by": used_by,
            "status": flags or ["OK"],
            "path": path,
        })

    issues = []
    tags = set()

    if bad_named:
        issues.append(
            f"{len(bad_named)} known-bad module name(s) loaded"
        )
        tags.add("rogue_kernel_mod")

    if rogue:
        issues.append(
            f"{len(rogue)} rogue/untracked module(s) loaded"
        )
        tags.add("rogue_kernel_mod")

    if path_flags:
        issues.append(
            f"{len(path_flags)} module(s) loaded from unusual paths"
        )
        tags.add("kernel_mod_path")

    warn_state = bool(issues)

    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_dir = os.path.join(
            "data",
            "logs",
            "kernel_check",
        )

        os.makedirs(log_dir, exist_ok=True)

        export_path = os.path.join(
            log_dir,
            f"kernel_check_{timestamp}.json",
        )

        with open(
            export_path,
            "w",
            encoding="utf-8",
        ) as file:
            json.dump(
                {
                    "timestamp": datetime.now().isoformat(),
                    "profile": profile,
                    "kernel_release": krel,
                    "status": "warning" if warn_state else "ok",
                    "summary": {
                        "total_modules": len(module_log),
                        "known_bad_name": len(bad_named),
                        "rogue_untracked": len(rogue),
                        "unusual_paths": len(path_flags),
                        "unused_info": len(info_unused),
                    },
                    "modules": module_log,
                },
                file,
                indent=2,
            )

    except Exception:
        pass

    if silent:
        return {
            "status": "warning" if warn_state else "ok",
            "details": issues,
            "tags": sorted(tags),
        }

    clear_screen()
    _header()

    console.print(
        Panel.fit(
            f"[dim]Kernel:[/] [white]{krel or 'Unknown'}[/]   "
            f"[dim]Loaded:[/] [white]{len(module_log)}[/]   "
            f"[dim]Warnings:[/] "
            f"[{'yellow' if warn_state else 'green'}]"
            f"{len(issues)}[/]   "
            f"[dim]Unused:[/] [white]{len(info_unused)}[/]",
            title="[bold cyan]SUMMARY[/]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )
    console.print()

    table = Table(
        title="[italic cyan]Loaded Kernel Modules[/]",
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
        show_edge=False,
        padding=(0, 1),
    )

    table.add_column(
        "Module",
        style="cyan",
        no_wrap=True,
    )
    table.add_column(
        "Size",
        style="white",
        justify="right",
    )
    table.add_column(
        "Used",
        style="white",
        justify="right",
    )
    table.add_column(
        "Status",
        no_wrap=True,
    )
    table.add_column(
        "Path",
        style="dim",
        overflow="fold",
    )

    for module in module_log:
        table.add_row(
            module["name"],
            module["size"],
            module["used_by"],
            _status_text(module["status"]),
            module["path"],
        )

    console.print(table)
    console.print()

    if warn_state:
        body = "\n".join(
            f"[yellow]{issue}[/]"
            for issue in issues
        )

        console.print(
            Panel.fit(
                body
                + "\n[dim]Validate module origin, path, and expected system role.[/]",
                title="[bold yellow]REVIEW REQUIRED[/]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )

    else:
        console.print(
            Panel.fit(
                "[green]No suspicious kernel module signals detected.[/]\n"
                "[dim]Loaded modules resolved within the expected kernel module tree.[/]",
                title="[bold green]STATUS: OK[/]",
                border_style="green",
                box=box.ROUNDED,
            )
        )

    pause_return()

    return {
        "status": "warning" if warn_state else "ok",
        "details": issues,
        "tags": sorted(tags),
    }