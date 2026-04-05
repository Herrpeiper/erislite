# Project: ErisLITE
# Module: network_menu.py
# Author: Liam Piper-Brandon
# Version: 1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-04-05
# Description: Network tools menu.

from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

from ui.utils import clear_screen, show_header

from core import network_tools

console = Console()

def run(profile: dict):
    while True:
        clear_screen()
        show_header("NETWORK TOOLS")

        table = Table(show_header=False, box=None)
        table.add_row("[1]", "📡  Show IP Addresses")
        table.add_row("", "")
        table.add_row("[2]", "🧭  Show Default Gateway")
        table.add_row("", "")
        table.add_row("[3]", "🌐  Show DNS Servers")
        table.add_row("", "")
        table.add_row("[4]", "📶  Ping a Host")
        table.add_row("", "")
        table.add_row("[5]", "🌎  Show External IP")
        table.add_row("", "")
        table.add_row("[6]", "🔗  Show Active Connections")
        table.add_row("", "")
        table.add_row("[7]", "🧭  Trace Route to Host")
        table.add_row("", "")
        table.add_row("[8]", "📝  WHOIS Lookup")
        table.add_row("", "")
        table.add_row("[9]", "🔙  Return to Main Menu")

        console.print(table)

        choice = input("\nSelect an option: ").strip()

        if choice == "1":
            network_tools.show_ips()
        elif choice == "2":
            network_tools.show_gateway()
        elif choice == "3":
            network_tools.show_dns()
        elif choice == "4":
            network_tools.ping_host()
        elif choice == "5":
            network_tools.show_external_ip()
        elif choice == "6":
            network_tools.show_active_connections()
        elif choice == "7":
            network_tools.trace_route()
        elif choice == "8":
            network_tools.whois_lookup()
        elif choice == "9":
            break

