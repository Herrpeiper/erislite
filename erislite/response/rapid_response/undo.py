import json
from pathlib import Path

from rich import box
from rich.prompt import Confirm, Prompt
from rich.table import Table

from erislite.response.rapid_response.utils import LOG_DIR, run_cmd
from erislite.ui.console import console
from erislite.ui.utils import clear_screen, pause_return


def run_undo(log_file: Path) -> None:
    clear_screen()

    if not log_file.exists():
        console.print(f"[red]Log file not found: {log_file}[/]")
        pause_return()
        return

    with open(log_file, "r", encoding="utf-8") as file:
        entries = json.load(file).get("actions", [])

    undoable = [entry for entry in entries if entry.get("undo")]

    if not undoable:
        console.print("[yellow]No undoable actions found in this log.[/]")
        pause_return()
        return

    console.print(f"[bold cyan]Undoable Actions ({len(undoable)})[/]\n")

    for index, entry in enumerate(undoable, start=1):
        console.print(f"[cyan][{index}][/] {entry['type']} — {entry['undo']}")

    console.print()

    if not Confirm.ask("[yellow]Run all undo commands?[/]", default=False):
        console.print("[yellow]Undo cancelled.[/]")
        pause_return()
        return

    for entry in undoable:
        rc, _, err = run_cmd(entry["undo"].split())

        if rc == 0:
            console.print(f"[green]Undone:[/] {entry['undo']}")
        else:
            console.print(f"[red]Failed:[/] {entry['undo']} — {err}")

    pause_return()


def select_and_undo() -> None:
    clear_screen()

    if not LOG_DIR.exists():
        console.print("[yellow]No rapid response logs found.[/]")
        pause_return()
        return

    logs = sorted(LOG_DIR.glob("rapid_response_*.json"), reverse=True)

    if not logs:
        console.print("[yellow]No rapid response logs found.[/]")
        pause_return()
        return

    table = Table(
        title="[italic cyan]Available Response Logs[/]",
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
        show_edge=False,
        padding=(0, 1),
    )
    table.add_column("Index", style="cyan", justify="right")
    table.add_column("File")
    table.add_column("Timestamp", style="dim")

    for index, log in enumerate(logs, start=1):
        try:
            with open(log, "r", encoding="utf-8") as file:
                timestamp = json.load(file).get("timestamp", "—")
        except Exception:
            timestamp = "—"

        table.add_row(str(index), log.name, timestamp)

    console.print(table)

    choice = Prompt.ask(
        "\n[cyan]Select a log[/] [dim](0 to cancel)[/]",
        default="0",
    )

    if choice == "0":
        return

    try:
        run_undo(logs[int(choice) - 1])
    except (ValueError, IndexError):
        console.print("[red]Invalid selection.[/]")
        pause_return()