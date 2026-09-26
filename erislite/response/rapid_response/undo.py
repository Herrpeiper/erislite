# Project: ErisLITE
# Module: undo.py
# Author: Liam Piper-Brandon
# Version: 1.3.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-26
# Description: Rapid Response rollback and undo operations.

import json
import shlex
import shutil
from pathlib import Path

from rich import box
from rich.prompt import Confirm, Prompt
from rich.table import Table

from erislite.network.firewall import build_ip_block_commands
from erislite.response.rapid_response.utils import LOG_DIR, run_cmd
from erislite.ui.console import console
from erislite.ui.utils import clear_screen, pause_return


def _format_undo(undo) -> str:
    if isinstance(undo, list):
        return " ".join(str(part) for part in undo)

    if isinstance(undo, dict):
        if undo.get("type") == "restore_file":
            return (
                f"restore {undo.get('source', '?')} "
                f"→ {undo.get('destination', '?')}"
            )

    return str(undo)


def _validate_command_undo(entry: dict, args: list[str]) -> bool:
    """
    Only allow command-based undo operations that match actions
    ErisLITE itself creates.
    """
    if not args:
        return False

    action_type = entry.get("type")
    data = entry.get("data", {})

    if action_type == "block_ip":
        ip = data.get("remote_ip")
        backend = data.get("firewall_backend")

        if not ip or not backend:
            return False

        commands = build_ip_block_commands(
            ip,
            backend,
        )

        if commands is None:
            return False

        return args == commands["undo"]

    if action_type == "lock_user":
        username = data.get("username")

        return args == [
            "usermod",
            "-U",
            username,
        ]

    return False


def _restore_file(entry: dict, undo: dict) -> tuple[bool, str]:
    if undo.get("type") != "restore_file":
        return False, "Unsupported file undo operation"

    source = undo.get("source")
    destination = undo.get("destination")

    if not source or not destination:
        return False, "Invalid restore-file metadata"

    expected_destination = entry.get("data", {}).get("path")

    if destination != expected_destination:
        return False, "Restore destination does not match original action"

    if not source.startswith(f"{destination}.rr_backup_"):
        return False, "Backup path does not match expected Rapid Response backup"

    source_path = Path(source)

    if not source_path.is_file():
        return False, f"Backup file not found: {source}"

    try:
        shutil.copy2(source, destination)
        return True, f"Restored {destination}"

    except Exception as exc:
        return False, str(exc)


def _execute_undo(entry: dict) -> tuple[bool, str]:
    undo = entry.get("undo")

    if isinstance(undo, dict):
        return _restore_file(entry, undo)

    if isinstance(undo, list):
        args = [str(part) for part in undo]

    elif isinstance(undo, str):
        # Compatibility with older v1.2 Rapid Response logs.
        try:
            args = shlex.split(undo)
        except ValueError as exc:
            return False, f"Invalid legacy undo command: {exc}"

    else:
        return False, "Unsupported undo format"

    if not _validate_command_undo(entry, args):
        return False, "Undo command failed validation"

    rc, _, err = run_cmd(args)

    if rc != 0:
        return False, err or "Undo command failed"

    return True, _format_undo(args)

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
        console.print(
            f"[cyan][{index}][/] "
            f"{entry['type']} — "
            f"{_format_undo(entry['undo'])}"
        )

    console.print()

    if not Confirm.ask("[yellow]Run all undo operations?[/]", default=False):
        console.print("[yellow]Undo cancelled.[/]")
        pause_return()
        return

    for entry in undoable:
        success, detail = _execute_undo(entry)

        if success:
            console.print(
                f"[green]Undone:[/] {_format_undo(entry['undo'])}"
            )
        else:
            console.print(
                f"[red]Failed:[/] "
                f"{_format_undo(entry['undo'])} — {detail}"
            )

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
