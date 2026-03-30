# Project: ErisLITE
# Module: kernel_module_check.py
# Author: Liam Piper-Brandon
# Version: 0.7
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-03-29
# Description: Kernel module inspection: known-bad names, untracked modules, unusual paths.

import subprocess
import os
import json
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.align import Align

from ui.utils import clear_screen, show_header, pause_return, get_os

console = Console()

# Keep this list SMALL and only include names you truly want to treat as “known-bad”.
# (Do not include normal drivers like btusb, loop, vboxdrv, etc.)
KNOWN_BAD_MODULES = {
    "adore", "diamorphine", "suterusu", "rootkit", "hideproc", "hideme",
    "kbeast", "reptile", "mushroom",
}

# You could expand this with more checks, like looking for modules with suspicious parameters, or cross-referencing against a known-good baseline for the specific kernel version.
def _kernel_release() -> str:
    try:
        return subprocess.check_output(["uname", "-r"], text=True).strip()
    except Exception:
        return ""

# This function tries to get the filesystem path of a loaded module using modinfo. If modinfo fails (e.g. because the module is rogue or hidden), it returns "Unknown
def get_module_path(modname: str) -> str:
    try:
        # Returns a filesystem path like /lib/modules/<krel>/kernel/.../foo.ko.xz
        out = subprocess.check_output(["modinfo", "-n", modname], text=True).strip()
        return out
    except Exception:
        return "Unknown"

# This function gets the list of currently loaded kernel modules by parsing the output of lsmod. It returns a list of tuples containing the module name, size, and used_by count.
def get_loaded_modules():
    """
    Returns list of (name, size, used_by)
    """
    try:
        result = subprocess.run(["lsmod"], capture_output=True, text=True)
        lines = result.stdout.strip().split("\n")[1:]  # skip header
        modules = []
        for line in lines:
            parts = line.split()
            if len(parts) >= 3:
                modules.append((parts[0], parts[1], parts[2]))
        return modules
    except Exception as e:
        return [("Error", "-", str(e))]

# Main function to run the kernel module check. If silent=True, it returns a structured result instead of printing to the console. The profile parameter is included in the exported JSON for context.
def run_kernel_module_check(silent: bool = False, profile: str = "default"):
    os_type = get_os()

    if os_type != "Linux":
        if not silent:
            clear_screen()
            show_header("KERNEL MODULE CHECK")
            console.print("[yellow]This module is only supported on Linux.[/]")
            pause_return()
        return {"status": "unsupported", "details": [], "tags": []}

    krel = _kernel_release()
    expected_prefix = f"/lib/modules/{krel}/" if krel else "/lib/modules/"

    modules = get_loaded_modules()

    bad_named = []      # KNOWN_BAD_MODULES
    rogue = []          # modinfo fails OR path not under expected prefix
    path_flags = []     # resolved path but not under expected prefix (kept separate if you want)
    info_unused = []    # legit but used_by == 0

    tags = []
    issues = []
    module_log = []

    table = Table(title="Kernel Module Check", show_lines=True)
    table.add_column("Module")
    table.add_column("Size")
    table.add_column("Used By")
    table.add_column("Status")
    table.add_column("Path")

    for name, size, used_by in modules:
        if name == "Error":
            table.add_row(name, size, used_by, "[red]Error[/]", "-")
            continue

        path = get_module_path(name)
        status_flags = []
        status = "[green]OK[/]"

        # 1) Known-bad name: high signal
        if name in KNOWN_BAD_MODULES:
            status_flags.append("KnownBadName")
            status = "[red]Known-bad module name[/]"
            bad_named.append(name)

        # 2) Legitimacy: modinfo resolves AND points to this kernel’s module tree
        is_legit = (path != "Unknown") and (expected_prefix in path)

        if not is_legit:
            # If modinfo failed, it's suspicious; if it resolved but path is weird, also suspicious
            status_flags.append("Rogue/Untracked")
            status = "[red]Rogue / Untracked[/]"
            rogue.append(name)

            if path != "Unknown" and expected_prefix not in path:
                status_flags.append("UnusualPath")
                path_flags.append((name, path))

        else:
            # Legit module
            if used_by == "0":
                status_flags.append("Unused")
                status = "[blue]Info[/], [magenta]Unused[/]"
                info_unused.append(name)

        table.add_row(name, size, used_by, status, path)

        module_log.append({
            "name": name,
            "size": size,
            "used_by": used_by,
            "status": status_flags if status_flags else ["OK"],
            "path": path
        })

    # Export scan to JSON (kept as you had it)
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_dir = os.path.join("data", "logs", "kernel_check")
        os.makedirs(log_dir, exist_ok=True)
        export_path = os.path.join(log_dir, f"kernel_check_{timestamp}.json")

        warn_state = bool(bad_named or rogue or path_flags)

        with open(export_path, "w") as f:
            json.dump({
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
                "modules": module_log
            }, f, indent=2)
    except Exception:
        pass

    # Silent return (for threat_sweep)
    if silent:
        if bad_named:
            issues.append(f"{len(bad_named)} known-bad module name(s) loaded")
            tags.append("rogue_kernel_mod")

        if rogue:
            issues.append(f"{len(rogue)} rogue/untracked module(s) loaded")
            tags.append("rogue_kernel_mod")

        if path_flags:
            issues.append(f"{len(path_flags)} module(s) loaded from unusual paths")
            tags.append("kernel_mod_path")

        # NOTE: unused modules are informational, not a warning
        return {
            "status": "warning" if issues else "ok",
            "details": issues,
            "tags": tags
        }

    # Interactive output mode
    clear_screen()
    show_header("KERNEL MODULE CHECK")
    console.print(Align.center(table))

    if bad_named or rogue or path_flags:
        if bad_named:
            console.print(f"\n[bold red]⚠️ Known-bad module names:[/] {', '.join(bad_named)}")
        if rogue:
            console.print(f"[bold red]⚠️ Rogue/untracked modules:[/] {', '.join(rogue)}")
        if path_flags:
            console.print(f"[bold yellow]⚠️ Modules with unusual paths:[/]")
            for n, p in path_flags:
                console.print(f"  - {n}: [dim]{p}[/]")
    else:
        console.print("\n[green]✅ No suspicious kernel module signals detected.[/]")

    pause_return()
    return {"status": "warning" if (bad_named or rogue or path_flags) else "ok", "details": [], "tags": []}
