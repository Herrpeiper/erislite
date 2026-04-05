# Project: ErisLITE
# Module: listener_check.py
# Author: Liam Piper-Brandon
# Version: 1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-04-05
# Description: Heuristic suspicious network listener detection.

import subprocess, re

from rich.console import Console
from rich.table import Table
from rich.align import Align

from ui.utils import clear_screen, show_header, pause_return, get_os

console = Console()

# Expected/common daemons (tune as you like)
WHITELISTED_PROCS = {
    "sshd",
    "cupsd",
    "avahi-daemon",
    "NetworkManager",
    "systemd-resolved",
}

# Processes that are commonly abused *as listeners*
# If these are listening, it's more suspicious.
SUSPICIOUS_PROC_NAMES = {"nc", "ncat", "socat"}

UNCOMMON_PORT_THRESHOLD = 1024

# Note: This is a heuristic and may not be perfect. Some processes may have multiple instances or dynamic names.
def extract_process_name(pid_info: str) -> str:
    match = re.search(r'users:\(\("([^"]+)"', pid_info)
    return match.group(1) if match else "unknown"

# Parses the local address to extract the port number. Returns 0 if parsing fails.
def _parse_port(local_address: str) -> int:
    if ":" not in local_address:
        return 0
    port_str = local_address.rsplit(":", 1)[-1]
    try:
        return int(port_str)
    except ValueError:
        return 0

# Determines if the local address indicates an external bind (exposure). This is a heuristic:
def _is_external_bind(local_address: str) -> bool:
    # All-interface binds are exposure, not inherently suspicious
    if "0.0.0.0" in local_address:
        return True
    if "[::]" in local_address:
        return True
    # Sometimes ss shows :: without brackets
    if local_address.startswith("::"):
        return True
    return False

# Main parsing function that runs "ss -tulnp" and extracts relevant info, applying heuristics to flag notable listeners.
def parse_listeners():
    """
    Returns list of:
      (proto, local_address, proc_name, flags:list[str], is_whitelisted:bool)
    """
    try:
        result = subprocess.run(["ss", "-tulnp"], capture_output=True, text=True)
        lines = result.stdout.splitlines()
        flagged = []

        for line in lines[1:]:  # skip header
            parts = line.split()
            if len(parts) < 5:
                continue

            proto = parts[0].lower()
            local_address = parts[4]
            pid_info = parts[-1] if parts[-1].startswith("users:") else ""
            proc_name = extract_process_name(pid_info).strip()

            port = _parse_port(local_address)
            is_whitelisted = proc_name in WHITELISTED_PROCS

            flags = []

            # Exposure / info flags
            if _is_external_bind(local_address):
                flags.append("🌐 External Bind")

            if port > UNCOMMON_PORT_THRESHOLD:
                flags.append("📶 High Port")

            # Suspicious capability flag
            if proc_name.lower() in SUSPICIOUS_PROC_NAMES:
                flags.append("🧪 Potential LOLBin Listener")

            # Mark known service (calms the output)
            if is_whitelisted:
                flags.append("✅ Known Service")

            # Only include rows that have something notable
            # (i.e., anything besides just "Known Service")
            notable = [f for f in flags if f != "✅ Known Service"]
            if not notable:
                continue

            flagged.append((proto, local_address, proc_name, flags, is_whitelisted))

        return flagged

    except Exception as e:
        return [("error", "-", f"{e}", ["⚠️ Error"], False)]

# Main function to run the listener scan, display results, and return structured output for Threat Sweep integration.
def run_listener_scan(silent: bool = False):
    os_type = get_os()

    if os_type != "Linux":
        if not silent:
            clear_screen()
            show_header("LISTENER SCAN")
            console.print("[yellow]This module is only supported on Linux.[/]")
            pause_return()
        return {"status": "unsupported", "details": [], "tags": []}

    flagged = parse_listeners()

    # Compute "suspicious subset" count
    suspicious = 0
    for proto, addr, proc, flags, is_whitelisted in flagged:
        has_lolbin = any("LOLBin" in f for f in flags)
        has_external = any("External Bind" in f for f in flags)
        has_high_port = any("High Port" in f for f in flags)

        # Suspicious rules:
        # 1) LOLBin listener is suspicious
        if has_lolbin:
            suspicious += 1
            continue

        # 2) Unknown (not whitelisted) exposed externally is suspicious
        if (not is_whitelisted) and has_external:
            suspicious += 1
            continue

        # 3) Unknown (not whitelisted) on high port is suspicious
        if (not is_whitelisted) and has_high_port:
            suspicious += 1
            continue

    # SILENT MODE (for Threat Sweep)
    if silent:
        if not flagged:
            return {"status": "ok", "details": [], "tags": []}

        # If nothing meets suspicious criteria, treat as OK (exposure only)
        if suspicious == 0:
            return {
                "status": "ok",
                "details": [f"{len(flagged)} listener(s) detected (expected/exposure)"],
                "tags": ["listener_exposure"]
            }

        return {
            "status": "warning",
            "details": [f"{suspicious} suspicious listener(s) detected ({len(flagged)} total notable)"],
            "tags": ["suspicious_listener"]
        }

    # INTERACTIVE MODE
    clear_screen()
    show_header("LISTENER SCAN")

    if not flagged:
        console.print("[green]No notable listeners detected.[/]")
        pause_return()
        return {"status": "ok", "details": [], "tags": []}

    table = Table(title="Listener Exposure & Suspicion", show_lines=True)
    table.add_column("Proto")
    table.add_column("Local Address")
    table.add_column("Process")
    table.add_column("Severity")
    table.add_column("Flags")

    for proto, addr, proc, flags, is_whitelisted in flagged:
        has_lolbin = any("LOLBin" in f for f in flags)
        has_external = any("External Bind" in f for f in flags)
        has_high_port = any("High Port" in f for f in flags)

        sev = "INFO"
        if has_lolbin:
            sev = "WARN"
        elif (not is_whitelisted) and (has_external or has_high_port):
            sev = "WARN"

        table.add_row(proto, addr, proc, sev, ", ".join(flags))

    console.print(Align.center(table))
    pause_return()

    # Return overall status based on suspicious subset
    if suspicious == 0:
        return {
            "status": "ok",
            "details": [f"{len(flagged)} listener(s) detected (expected/exposure)"],
            "tags": ["listener_exposure"]
        }

    return {
        "status": "warning",
        "details": [f"{suspicious} suspicious listener(s) detected ({len(flagged)} total notable)"],
        "tags": ["suspicious_listener"]
    }
