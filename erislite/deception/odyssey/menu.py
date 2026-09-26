# Project: ErisLITE
# Module: menu.py
# Author: Liam Piper-Brandon
# Version: 1.4.0
# License: MIT
# Created: 2026-09-26
# Last Updated: 2026-09-26
# Description: Interactive control and status interface for Odyssey Lite.

from rich import box
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from erislite.config.settings import APP_NAME, APP_VERSION
from erislite.deception.odyssey.manager import OdysseyManager
from erislite.ui.console import console
from erislite.ui.utils import clear_screen, pause_return


def _header() -> None:
    """Render the Odyssey Lite header."""

    console.print(
        Panel(
            Text.from_markup(
                "[dim]Deception and early-warning monitoring[/]"
            ),
            title="[bold cyan]ODYSSEY LITE[/]",
            subtitle=f"[dim cyan]{APP_NAME} v{APP_VERSION}[/]",
            border_style="cyan",
            box=box.SQUARE,
            padding=(0, 1),
        )
    )
    console.print()


def _status_panel(manager: OdysseyManager) -> None:
    """Render current Odyssey status."""

    if manager.running:
        status = "[bold green]ACTIVE[/]"
    else:
        status = "[dim]INACTIVE[/]"

    body = Text.from_markup(
        f"[dim]Status:[/] {status}\n"
        f"[dim]Listeners:[/] [white]{len(manager.listeners)}[/]\n"
        f"[dim]Events:[/] [white]{len(manager.events)}[/]"
    )

    console.print(
        Panel.fit(
            body,
            title="[bold cyan]Status[/]",
            border_style="cyan" if manager.running else "grey37",
            box=box.ROUNDED,
        )
    )
    console.print()


def _build_menu(manager: OdysseyManager) -> Table:
    """Build the Odyssey Lite action menu."""

    menu = Table(
        show_header=False,
        box=None,
        padding=(0, 1),
        collapse_padding=True,
    )

    menu.add_column(no_wrap=True)
    menu.add_column()
    menu.add_column()

    menu.add_row("[bold cyan]MONITORING[/]", "", "")

    if manager.running:
        menu.add_row(
            "[dim][1][/]",
            "[dim]Start Odyssey[/]",
            "[dim]Already active[/]",
        )
        menu.add_row(
            "[yellow][2][/]",
            "Stop Odyssey",
            "[dim]Stop canary listeners[/]",
        )
    else:
        menu.add_row(
            "[green][1][/]",
            "Start Odyssey",
            "[dim]Activate canary listeners[/]",
        )
        menu.add_row(
            "[dim][2][/]",
            "[dim]Stop Odyssey[/]",
            "[dim]Already stopped[/]",
        )

    menu.add_row(
        "[cyan][3][/]",
        "Recent Events",
        "[dim]View observed connections[/]",
    )
    menu.add_row(
        "[cyan][4][/]",
        "Listener Status",
        "[dim]View configured canaries[/]",
    )
    menu.add_row(
        "[cyan][5][/]",
        "Clear Events",
        "[dim]Clear current event history[/]",
    )

    menu.add_row("", "", "")
    menu.add_row("[cyan][0][/]", "Back", "")

    return menu


def _show_listener_status(manager: OdysseyManager) -> None:
    """Display the current Odyssey listener configuration and state."""

    clear_screen()
    _header()

    table = Table(
        title="[italic cyan]Canary Listeners[/]",
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
        show_edge=False,
        padding=(0, 1),
    )

    table.add_column("Port", style="cyan", justify="right")
    table.add_column("Service", style="white")
    table.add_column("Severity")
    table.add_column("Enabled")
    table.add_column("State")

    active_ports = {
        listener.config.port
        for listener in manager.listeners
        if listener.running
    }

    for config in manager.configs:
        if config.severity == "high":
            severity = "[red]HIGH[/]"
        elif config.severity == "medium":
            severity = "[yellow]MEDIUM[/]"
        else:
            severity = f"[white]{config.severity.upper()}[/]"

        enabled = (
            "[green]YES[/]"
            if config.enabled
            else "[dim]NO[/]"
        )

        if config.port in active_ports:
            state = "[bold green]LISTENING[/]"
        elif not config.enabled:
            state = "[dim]DISABLED[/]"
        else:
            state = "[dim]STOPPED[/]"

        table.add_row(
            str(config.port),
            config.service,
            severity,
            enabled,
            state,
        )

    console.print(table)
    console.print()

    pause_return()

def _show_recent_events(manager: OdysseyManager) -> None:
    """Display recently observed Odyssey events."""

    clear_screen()
    _header()

    events = manager.events

    if not events:
        console.print(
            Panel.fit(
                "[dim]No Odyssey events have been observed.[/]",
                title="[dim cyan]Recent Events[/]",
                border_style="grey37",
                box=box.ROUNDED,
            )
        )
        console.print()
        pause_return()
        return

    table = Table(
        title=f"[italic cyan]Recent Events ({len(events)})[/]",
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
        show_edge=False,
        padding=(0, 1),
    )

    table.add_column("Time", style="white", no_wrap=True)
    table.add_column("Source", style="white")
    table.add_column("Port", style="cyan", justify="right")
    table.add_column("Service", style="white")
    table.add_column("Severity")

    for event in reversed(events):
        if event.severity == "high":
            severity = "[red]HIGH[/]"
        elif event.severity == "medium":
            severity = "[yellow]MEDIUM[/]"
        else:
            severity = f"[white]{event.severity.upper()}[/]"

        timestamp = event.timestamp.astimezone().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        source = f"{event.source_ip}:{event.source_port}"

        table.add_row(
            timestamp,
            source,
            str(event.destination_port),
            event.service,
            severity,
        )

    console.print(table)
    console.print()

    pause_return()

def run_odyssey_menu(manager: OdysseyManager | None = None) -> None:
    """Run the interactive Odyssey Lite control menu."""

    if manager is None:
        manager = OdysseyManager()

    while True:
        clear_screen()

        _header()
        _status_panel(manager)

        console.print(_build_menu(manager))

        choice = Prompt.ask(
            "\n[cyan]Select an option[/]",
            choices=["0", "1", "2", "3", "4", "5"],
            default="0",
        )

        if choice == "0":
            break

        if choice == "1":
            if manager.running:
                continue

            try:
                manager.start()
            except OSError as exc:
                console.print()
                console.print(
                    f"[bold red]Odyssey failed to start:[/] {exc}"
                )
                pause_return()

        elif choice == "2":
            if not manager.running:
                continue

            manager.stop()

        elif choice == "3":
            _show_recent_events(manager)

        elif choice == "4":
            _show_listener_status(manager)

        elif choice == "5":
            if not manager.events:
                continue

            if Confirm.ask(
                "[yellow]Clear all Odyssey event history?[/]",
                default=False,
            ):
                manager.clear_events()
