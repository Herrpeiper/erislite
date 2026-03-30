# Project: ErisLITE
# Module: utils.py
# Author: Liam Piper-Brandon
# Version: 0.7
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-03-29
# Description: Shared UI utilities: clear_screen, show_header, pause_return, get_os.

import os, platform, json

from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.align import Align

console = Console()

def get_os():
    """
    Returns 'Windows', 'Linux', or 'Other'
    """
    system = platform.system()
    if system == "Windows":
        return "Windows"
    elif system == "Linux":
        return "Linux"
    else:
        return "Other"

def clear_screen():
    os.system("cls" if get_os() == "Windows" else "clear")

def show_header(title="ERISLITE"):
    console.print(Panel(title, style="bold cyan", border_style="cyan"))

def pause_return(centered=True):
    message = "\nPress [ENTER] to return to the menu..."
    if centered:
        console.print(Align.center(message))
    else:
        console.print(message)
    input()

def export_json_log(data, prefix="log", folder="logs"):
    """Export structured data to a JSON file with timestamped name."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(folder, exist_ok=True)
    filename = f"{prefix}_{timestamp}.json"
    filepath = os.path.join(folder, filename)
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)
    return filepath
