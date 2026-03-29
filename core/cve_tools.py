# Project: ErisLITE
# Module: cve_tools.py
# Author: Liam Piper-Brandon
# Version: 0.5
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-03-17
# Description:
#   This module provides tools for searching and displaying CVE information from a local cache. It
#   is designed to be used in offline mode, allowing users to query CVEs by ID, keyword, or tag and 
#   view details in a readable format. The CVE cache is expected to be a JSON file containing relevant CVE data.

import json, os

from rich.console import Console
from rich.table import Table

console = Console()

# Load CVE cache from local JSON file
def load_cve_cache(path="data/cve/cve_cache.json"):
    if not os.path.exists(path):
        console.print("[bold red]CVE cache not found.[/bold red]")
        return []
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception as e:
        console.print(f"[bold red]Error loading CVE cache:[/bold red] {e}")
        return []

# Search CVEs based on query (CVE ID, keyword, or tag)
def search_cves(query, cache):
    query = query.lower()
    return [
        cve for cve in cache
        if query in cve["cve_id"].lower()
        or query in cve["description"].lower()
        or any(query in tag.lower() for tag in cve.get("tags", []))
    ]

# Display CVE search results in a readable format
def display_results(results):
    if not results:
        console.print("[yellow]No matching CVEs found.[/yellow]")
        return

    for cve in results:
        table = Table(title=f"{cve['cve_id']} — {cve['severity']}", style="bold cyan")
        table.add_column("Field", style="bold green", no_wrap=True)
        table.add_column("Details", style="white")

        table.add_row("Description", cve.get("description", "N/A"))
        table.add_row("Affected", ", ".join(cve.get("affected", [])))
        table.add_row("Tags", ", ".join(cve.get("tags", [])))

        console.print(table)
        console.print()

# Main function to run the CVE search tool
def run_cve_tool():
    console.print("\n[bold cyan]ErisLite CVE Search (Offline Mode)[/bold cyan]")
    cache = load_cve_cache()
    if not cache:
        return

    while True:
        query = console.input("[bold]> Enter CVE ID or keyword (or 'q' to quit): [/bold]")
        if query.lower() in ("q", "quit", "exit"):
            break
        results = search_cves(query, cache)
        display_results(results)
