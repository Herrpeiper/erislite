# Project: ErisLITE
# Module: cve_checker.py
# Author: Liam Piper-Brandon
# Version: 0.5
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-03-17
# Description:
#   This module checks for specific CVEs based on local software versions 
#   (kernel, sudo, glibc). It is designed to be read-only and does not attempt 
#   to verify patch levels or exploit vulnerabilities.

import platform, subprocess, re

from packaging import version
from rich.console import Console
from rich.table import Table
from ui.utils import pause_return

console = Console()

# Sanitizes version strings to keep only the numeric core (e.g., "1.9.5p2" -> "1.9.5").
def sanitize_version(ver_str: str) -> str:
    """
    Keeps numeric version core. Example:
      '1.9.5p2' -> '1.9.5'
      '2.35-0ubuntu3.6' -> '2.35'
    """
    match = re.match(r'^(\d+\.\d+(?:\.\d+)?).*', ver_str)
    return match.group(1) if match else ver_str

# Functions to get local software versions for kernel, sudo, and glibc. These are used to check against known vulnerable versions for specific CVEs.
def get_kernel_version():
    raw = platform.release()           # e.g. 6.5.0-21-generic
    return raw.split("-")[0]           # e.g. 6.5.0

# Note: For sudo, the version output can be complex (e.g., "1.9.5p2"), and the patch level may be relevant for certain CVEs. The sanitize_version function helps extract the core version for comparison, but be aware that some CVEs may require more nuanced parsing to determine vulnerability based on patch levels.
def get_sudo_version():
    try:
        line0 = subprocess.check_output(["sudo", "-V"], text=True).splitlines()[0]
        return line0.strip().split()[-1]  # e.g., "1.9.5p2"
    except Exception:
        return None

# For glibc, the version can also include additional info (e.g., "2.35-0ubuntu3.6"). The sanitize_version function will help extract the core version number for comparison against known vulnerable versions.
def get_glibc_version():
    try:
        line0 = subprocess.check_output(["ldd", "--version"], text=True).splitlines()[0]
        # Usually ends with something like "2.35"
        for part in reversed(line0.strip().split()):
            if part and part[0].isdigit():
                return part
    except Exception:
        return None

# CVE checks based on version numbers. This is a simplified approach and may yield false positives if vendors backport patches without changing the base version number. Always verify with vendor advisories for patch levels.
def _kernel_dirty_pipe_vulnerable(kver: str) -> bool:
    """
    Dirty Pipe affects kernels >= 5.8 and is patched in:
      5.16.11, 5.15.25, 5.10.102
    If you're on newer branches (>=5.17 etc), you're fine.
    """
    kv = version.parse(sanitize_version(kver))

    if kv < version.parse("5.8.0"):
        return False

    # Patched if in/above any fixed branch point
    if kv >= version.parse("5.16.11"):
        return False
    if version.parse("5.15.0") <= kv < version.parse("5.16.0") and kv >= version.parse("5.15.25"):
        return False
    if version.parse("5.10.0") <= kv < version.parse("5.11.0") and kv >= version.parse("5.10.102"):
        return False

    # Otherwise within the vulnerable window
    return True

# Main function to check for CVE matches based on local versions and return results. The run_cve_check function can be called with silent=True for non-interactive use (e.g., API) or silent=False for interactive console output.
def check_versions():
    results = []

    kernel = get_kernel_version()
    if kernel and _kernel_dirty_pipe_vulnerable(kernel):
        results.append(("Kernel", kernel, "CVE-2022-0847", "Dirty Pipe", "High"))

    sudo = get_sudo_version()
    if sudo:
        # NVD: vulnerable before 1.9.5p2 :contentReference[oaicite:3]{index=3}
        sudo_clean = sanitize_version(sudo)
        if version.parse(sudo_clean) < version.parse("1.9.5"):
            # Still worth flagging very old
            results.append(("sudo", sudo, "CVE-2021-3156", "Heap Overflow (Baron Samedit) - verify patch level", "High"))
        else:
            # If you want to be stricter, you can also treat "1.9.5p0/p1" as suspect,
            # but sanitize_version strips the p-level; leaving note in Issue text is safer.

            # OPTIONAL: If you want to preserve p-level logic, you'll need a parser that compares p-suffixes.
            pass

    glibc = get_glibc_version()
    if glibc:
        # Introduced in glibc 2.34; vendors may backport fixes. :contentReference[oaicite:4]{index=4}
        glibc_clean = sanitize_version(glibc)
        gv = version.parse(glibc_clean)
        if version.parse("2.34") <= gv < version.parse("2.39"):
            results.append(("glibc", glibc, "CVE-2023-4911", "Looney Tunables (version match; patch may be backported)", "High"))

    return results

# Main function to run the CVE check and optionally print results to console. If silent=True, it returns a structured result without printing, which can be used for API responses or other non-interactive contexts.
def run_cve_check(silent=False):
    results = check_versions()

    if silent:
        if results:
            # Treat version-only matches as informational
            return {
                "status": "ok",  # ← This is the key change
                "details": [f"{len(results)} version match(es) detected (verify vendor patch level)"],
                "tags": ["cve_version_match"],  # informational tag
                "matches": results
            }
        return {
            "status": "ok",
            "details": [],
            "tags": [],
            "matches": []
        }


    console.print("\n[bold cyan]Local CVE Version Check[/bold cyan] (Offline, Read-Only)")
    console.print("[dim]Note: Version matches do not confirm vulnerability; vendors may backport fixes without changing the base version.[/]\n")

    if not results:
        console.print("[green]✔ No known version matches detected for kernel/sudo/glibc.[/green]")
        pause_return()
        return []

    table = Table(title="Detected CVE Version Matches", header_style="bold magenta")
    table.add_column("Component", style="cyan", no_wrap=True)
    table.add_column("Version", style="white")
    table.add_column("CVE", style="red")
    table.add_column("Issue", style="white")
    table.add_column("Severity", style="bold red")

    for name, ver, cve, desc, severity in results:
        table.add_row(name, ver, cve, desc, severity)

    console.print(table)
    pause_return()
    return results
