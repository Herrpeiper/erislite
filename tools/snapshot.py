# Project: ErisLITE
# Module: snapshot.py
# Author: Liam Piper-Brandon
# Version: 0.6
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-03-29
# Description:
#   This module captures a snapshot of the system's current state, including OS information, uptime,
#   logged-in users, network interfaces, and routing info. Results are saved to a timestamped log
#   file in the data/logs directory. The user profile is used to label the snapshot and drive
#   username recognition — no usernames are hardcoded.

import os, platform, socket, psutil

from datetime import timedelta, datetime

from rich.console import Console
from rich.panel import Panel

from ui.utils import clear_screen, show_header, pause_return

from core.security_audit import check_firewall_status

console = Console()

# Capture a system snapshot and save it to a timestamped file in the logs directory
def capture(profile: dict):
    clear_screen()
    show_header("SYSTEM SNAPSHOT")

    os_type = platform.system()
    now = datetime.now()
    timestamp = now.strftime("%Y-%m-%d_%H-%M-%S")
    hostname = profile.get("hostname") or socket.gethostname()
    hostname = hostname.replace(" ", "_")  # filesystem safe

    # Build the recognised-user whitelist from the profile instead of hardcoding names.
    # Pulls "known_users" list if present; falls back to just the hostname owner so the
    # snapshot never fires spurious UNRECOGNIZED alerts on a fresh deployment.
    profile_known = profile.get("known_users", [])
    if isinstance(profile_known, list):
        whitelist = set(u.lower() for u in profile_known if u)
    else:
        whitelist = set()

    log_dir = "data/logs"
    os.makedirs(log_dir, exist_ok=True)
    filename = f"{log_dir}/{hostname}_snapshot_{timestamp}.txt"

    try:
        with open(filename, "w") as f:
            # Session Header
            f.write("ErisLite System Snapshot\n")
            f.write(f"Timestamp: {timestamp}\n")
            f.write(f"Hostname: {hostname}\n")
            f.write(f"Role: {profile.get('role')}\n")
            f.write(f"Segment: {profile.get('segment')}\n")
            f.write(f"Analyst ID: {profile.get('analyst_id')}\n")
            f.write(f"Firewall: {check_firewall_status()}\n")
            f.write("-" * 40 + "\n\n")

            # System Info
            f.write("[System Info]\n")
            f.write(f"OS: {os_type} {platform.release()}\n")
            if os_type == "Windows":
                f.write(f"Build Version: {platform.version()}\n")
            else:
                f.write(f"Kernel: {platform.version()}\n")

            uptime_seconds = psutil.boot_time()
            uptime = timedelta(seconds=int(datetime.now().timestamp() - uptime_seconds))
            f.write(f"Uptime: {uptime}\n")

            users = psutil.users()
            unique_users = set(u.name for u in users)

            f.write(f"Logged-in Users: {len(users)}\n")
            flagged_users = []

            if unique_users:
                f.write("Active Usernames:\n")
                for user in sorted(unique_users):
                    if whitelist and user.lower() not in whitelist:
                        f.write(f" - {user}  ⚠️ [UNRECOGNIZED]\n")
                        flagged_users.append(user)
                    else:
                        f.write(f" - {user}\n")
            else:
                f.write("Active Usernames: none detected\n")

            if flagged_users:
                f.write(f"\n⚠️ ALERT: {len(flagged_users)} unknown user(s) detected!\n")

            f.write("\n")

            # Network Interfaces
            f.write("[Network Interfaces]\n")
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        f.write(f"{iface}: {addr.address}\n")

            # Default Gateway
            f.write("\n[Routing Info]\n")
            if os_type == "Linux":
                result = os.popen("ip route").read()
                for line in result.splitlines():
                    if line.startswith("default"):
                        parts = line.split()
                        if len(parts) > 4:
                            f.write(f"Default Gateway: {parts[2]} via {parts[4]}\n")
                        break
            elif os_type == "Windows":
                result = os.popen("route print").read()
                gateway_found = False
                for line in result.splitlines():
                    if "0.0.0.0" in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            f.write(f"Default Gateway: {parts[2]}\n")
                            gateway_found = True
                            break
                if not gateway_found:
                    f.write("Default Gateway: not detected\n")

        console.print(Panel.fit(f"[green]Snapshot saved to:[/] {filename}"))

    except Exception as e:
        console.print(f"[red]Error saving snapshot:[/] {e}")

    pause_return()
