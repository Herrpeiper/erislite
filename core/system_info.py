# Project: ErisLITE
# Module: system_info.py
# Author: Liam Piper-Brandon
# Version: 1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-04-05
# Description: System information display: OS, CPU, RAM, uptime, logged-in users.

import os, platform, psutil, getpass, time

from datetime import timedelta
from rich.console import Console
from rich.table import Table

from ui.utils import clear_screen, show_header

console = Console()

# Helper functions to get system information
def get_uptime():
    uptime_seconds = time.time() - psutil.boot_time()
    return str(timedelta(seconds=int(uptime_seconds)))

# Get OS information
def get_os_info():
    return f"{platform.system()} {platform.release()}"

# Get kernel version
def get_kernel_version():
    return platform.version()

# Get CPU information
def get_cpu_info():
    cpu_count = psutil.cpu_count(logical=True)
    cpu_model = platform.processor() or platform.machine()
    return f"{cpu_model} ({cpu_count} cores)"

# Get RAM information
def get_ram_info():
    ram = psutil.virtual_memory()
    ram_total = round(ram.total / (1024 ** 3), 2)
    ram_used = round(ram.used / (1024 ** 3), 2)
    ram_percent = ram.percent
    return f"{ram_used} GB / {ram_total} GB ({ram_percent}%)"

# Get logged-in users count
def get_logged_in_users():
    try:
        return len(psutil.users())
    except Exception:
        return 0

# Get system uptime
def get_uptime():
    uptime_seconds = time.time() - psutil.boot_time()
    return str(timedelta(seconds=int(uptime_seconds)))

# Get logged-in users count
def get_logged_in_users():
    try:
        return len(psutil.users())
    except Exception:
        return 0

# Main function to run the system info module
def run(profile: dict):
    clear_screen()
    show_header("SYSTEM INFO")

    try:
        uname = platform.uname()
        user = getpass.getuser()
        hostname = uname.node
        os_info = f"{uname.system} {platform.release()}"
        kernel = uname.release
        uptime = get_uptime()

        cpu_count = psutil.cpu_count(logical=True)
        cpu_model = uname.processor if uname.processor else platform.machine()

        ram = psutil.virtual_memory()
        ram_total = round(ram.total / (1024 ** 3), 2)
        ram_used = round(ram.used / (1024 ** 3), 2)
        ram_percent = ram.percent

        if platform.system() == "Linux":
            load1, load5, load15 = os.getloadavg()
        else:
            load1, load5, load15 = (None, None, None)

        logged_users = psutil.users()
        logged_user_count = len(logged_users)

        table = Table(title="System Overview", show_lines=True)
        table.add_column("Property", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")

        table.add_row("Hostname", hostname)
        table.add_row("OS", os_info)
        table.add_row("Kernel", kernel)
        table.add_row("Uptime", uptime)
        table.add_row("User (You)", user)
        table.add_row("Logged-In Users", str(logged_user_count))
        table.add_row("CPU", f"{cpu_model} ({cpu_count} cores)")
        table.add_row("RAM", f"{ram_used} GB / {ram_total} GB ({ram_percent}%)")

        if load1 is not None:
            table.add_row("Load Average", f"{load1:.2f}, {load5:.2f}, {load15:.2f}")
        else:
            table.add_row("Load Average", "[dim]Unavailable on this OS[/]")

        console.print(table)

    except Exception as e:
        console.print(f"[red]Error collecting system info:[/] {e}")

    input("\n[bold green]Press Enter to return to the main menu...[/]")
