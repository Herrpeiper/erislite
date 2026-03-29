from rich.console import Console
from rich.panel import Panel
from ui.utils import clear_screen, pause_return
from core.version import VERSION

console = Console()

def show_help():
    clear_screen()

    title = "[bold cyan]ErisLite Security Toolkit - Help / About[/]"
    description = (
        f"[green]Version:[/] {VERSION}\n"
        "[green]Developer:[/] Liam Piper-Brandon\n\n"
        "[bold]Description:[/]\n"
        "ErisLite is a modular system and network monitoring suite designed for CCDC competitions\n"
        "and educational security auditing. It provides snapshot logging, threat assessment,\n"
        "and a range of tools to quickly evaluate system state.\n\n"
        "[bold]Included Modules:[/]\n"
        "• [cyan]System Info[/] - Hardware, OS, uptime details\n"
        "• [cyan]Network Tools[/] - IP, gateway, DNS, ping, traceroute, WHOIS\n"
        "• [cyan]Security Tools[/] - Audits, file integrity, suspicious user/process detection\n"
        "• [cyan]Snapshot Logging[/] - System state snapshots saved to logs\n"
        "• [cyan]Threat Sweep[/] - Consolidated security checks with risk scoring\n\n"
        "[bold]Usage:[/]\n"
        "Navigate with the menu numbers. Results can be exported to logs in data/logs/.\n\n"
        "For more information, contact your administrator or consult the project documentation."
    )

    console.print(Panel.fit(description, title=title, border_style="magenta"))
    pause_return()