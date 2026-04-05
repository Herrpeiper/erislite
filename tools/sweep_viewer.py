# Project: ErisLITE
# Module: sweep_viewer.py
# Author: Liam Piper-Brandon
# Version: 1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-04-04
# Description: Threat sweep log viewer: browse and inspect past sweep results.

import os, json
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.align import Align
from rich.markdown import Markdown

from ui.utils import clear_screen, show_header, pause_return

LOG_DIR = "data/logs/threat_sweeps"
console = Console()

def load_sweep_logs(limit=5):
    if not os.path.exists(LOG_DIR):
        console.print("[red]No sweep logs found.[/]")
        return []

    logs = []

    for file in os.listdir(LOG_DIR):
        if file.startswith("sweep_log_") and file.endswith(".json"):
            path = os.path.join(LOG_DIR, file)
            try:
                with open(path, 'r') as f:
                    data = json.load(f)
                    logs.append((data.get("timestamp", "Unknown"), data, file))
            except Exception:
                continue

    logs.sort(key=lambda x: x[0], reverse=True)
    return logs[:limit]

def show_recent_sweeps(limit=5):
    logs = load_sweep_logs(limit)

    if not logs:
        console.print("[red]No recent sweep logs found.[/]")
        return []

    table = Table(title=f"Last {len(logs)} Threat Sweeps", show_lines=True)
    table.add_column("Timestamp", style="cyan")
    table.add_column("Profile", style="magenta")
    table.add_column("Risk Score", style="bold")
    table.add_column("Tags Detected", style="yellow")

    for timestamp, data, filename in logs:
        profile = data.get("sweep_profile", "unknown")
        score = str(data.get("risk_score", "N/A"))
        results = data.get("results", {})
        tag_set = set()
        for module_result in results.values():
            tag_set.update(module_result.get("tags", []))
        tags = ", ".join(sorted(tag_set)) if tag_set else "None"

        table.add_row(timestamp, profile, score, tags)

    console.print("\n")
    console.print(Align.center(table))
    console.print("\n")
    return logs

def view_full_report():
    logs = load_sweep_logs(limit=5)
    if not logs:
        console.print("[red]No recent sweep logs found.[/]")
        pause_return()
        return

    clear_screen()
    show_header("FULL THREAT SWEEP REPORT")

    table = Table(title="Select a Sweep Log", show_lines=True)
    table.add_column("Index", style="cyan", justify="center")
    table.add_column("Timestamp", style="magenta")
    table.add_column("Profile", style="green")
    table.add_column("Score", style="yellow")

    for i, (timestamp, data, filename) in enumerate(logs):
        table.add_row(
            str(i + 1),
            timestamp,
            data.get("sweep_profile", "unknown"),
            str(data.get("risk_score", "N/A"))
        )

    console.print(table)
    idx = input("\nSelect a log by index: ").strip()

    if not idx.isdigit() or not (1 <= int(idx) <= len(logs)):
        console.print("[red]Invalid selection.[/]")
        pause_return()
        return

    selected_data = logs[int(idx) - 1][1]  # JSON dict
    timestamp = selected_data.get("timestamp", "unknown")

    clear_screen()
    show_header(f"FULL REPORT – {timestamp}")

    # Metadata panel
    profile = selected_data.get("sweep_profile", "N/A").capitalize()
    score = selected_data.get("risk_score", "N/A")
    console.print(
        Panel.fit(
            f"[bold magenta]Profile:[/] {profile}   "
            f"[bold yellow]Risk Score:[/] {score}",
            title="Sweep Metadata"
        )
    )

    # Tags
    all_tags = set()
    for result in selected_data.get("results", {}).values():
        all_tags.update(result.get("tags", []))
    if all_tags:
        tag_str = ", ".join(sorted(all_tags))
        console.print(f"[bold red]Tags Detected:[/] {tag_str}\n")

    # Module Results
    for module, result in selected_data.get("results", {}).items():
        module_title = module.replace("_", " ").title()
        status = result.get("status", "UNKNOWN").upper()
        details = result.get("details", ["No details."])

        # Emoji + status formatting
        emoji = "✅" if status == "OK" else "⚠️" if status == "WARNING" else "❌"
        header = f"### {emoji} {module_title} – [{status}]"

        # Compose markdown
        markdown_block = f"{header}\n"
        for line in details:
            markdown_block += f"- {line}\n"
        markdown_block += "\n"

        console.print(Markdown(markdown_block))

    pause_return()


def sweep_viewer_menu():
    while True:
        clear_screen()
        show_header("SWEEP LOG VIEWER")

        menu = Table(show_header=False, box=None, padding=(0, 1))
        menu.add_row("[1]", "📂  View Recent Threat Sweeps")
        menu.add_row("", "")
        menu.add_row("[2]", "📄  View Full Report (Select by Timestamp)")
        menu.add_row("", "")
        menu.add_row("[3]", "↩️  Back to Security Tools Menu")
        console.print(menu)

        choice = input("\nSelect an option: ").strip()

        if choice == "1":
            clear_screen()
            show_header("RECENT SWEEP RESULTS")
            show_recent_sweeps()
            pause_return()
        elif choice == "2":
            view_full_report()
        elif choice == "3":
            break
        else:
            console.print("[red]Invalid selection.[/]")
            pause_return()

