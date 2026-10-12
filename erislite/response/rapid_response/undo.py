# Project: ErisLITE
# Module: undo.py
# Author: Liam Piper-Brandon
# Version: 1.5.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-10-12
# Description: Rapid Response rollback and undo operations.

import json
import os
import shlex
import stat
from pathlib import Path

from rich import box
from rich.prompt import Confirm, Prompt
from rich.table import Table

from erislite.network.firewall import build_ip_block_commands
from erislite.response.rapid_response import utils
from erislite.response.rapid_response.triage import CRON_DIRS
from erislite.response.rapid_response.utils import LOG_DIR, run_cmd
from erislite.security.safe_io import read_regular_bytes, write_private_bytes
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

        return args == commands["undo"] or args in _legacy_block_undos(ip, backend)

    if action_type == "lock_user":
        username = data.get("username")

        return args == [
            "usermod",
            "-U",
            username,
        ]

    return False


def _legacy_block_undos(ip: str, backend: str) -> list:
    """Undo commands written by ErisLITE 1.4 and earlier."""

    if backend == "firewalld":
        rule = f'rule family="ipv4" destination address="{ip}" drop'
        return [["firewall-cmd", f"--remove-rich-rule={rule}"]]

    return []


def _is_within(path: Path, directory: Path) -> bool:
    try:
        Path(os.path.abspath(path)).relative_to(os.path.abspath(directory))
    except ValueError:
        return False

    return True


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

    if os.path.dirname(os.path.abspath(destination)) not in CRON_DIRS:
        return False, "Restore destination is not inside a cron directory"

    if not _is_within(Path(source), Path(utils.QUARANTINE_DIR)):
        return False, "Backup path is not inside the Rapid Response quarantine"

    try:
        content = read_regular_bytes(source)
    except FileNotFoundError:
        return False, f"Quarantined copy not found: {source}"
    except OSError as exc:
        return False, str(exc)

    # Restore the job, not the weakness: the world-writable bit that got
    # the file flagged is never put back.
    mode = int(undo.get("mode", 0o644)) & 0o7777 & ~stat.S_IWOTH
    owner = (int(undo.get("uid", 0)), int(undo.get("gid", 0)))

    try:
        write_private_bytes(destination, content, mode=mode, owner=owner, create_dirs=False)
    except OSError as exc:
        return False, str(exc)

    return True, f"Restored {destination} (mode {mode:o}, world-write removed)"


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

def _log_is_trusted(log_file: Path) -> tuple[bool, str]:
    """Undo runs commands from the log, so only trust logs no one else could edit."""

    try:
        info = os.lstat(log_file)
    except OSError as exc:
        return False, str(exc)

    if not stat.S_ISREG(info.st_mode):
        return False, f"{log_file} is not a regular file"

    if info.st_uid not in (0, os.geteuid()):
        return False, f"{log_file} is owned by uid {info.st_uid}"

    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return False, f"{log_file} is writable by other users"

    return True, ""


def run_undo(log_file: Path) -> None:
    clear_screen()

    if not log_file.exists():
        console.print(f"[red]Log file not found: {log_file}[/]")
        pause_return()
        return

    trusted, reason = _log_is_trusted(log_file)

    if not trusted:
        console.print(f"[red]Refusing to use response log:[/] {reason}")
        pause_return()
        return

    try:
        entries = json.loads(read_regular_bytes(log_file)).get("actions", [])
    except (OSError, ValueError) as exc:
        console.print(f"[red]Could not read response log:[/] {exc}")
        pause_return()
        return

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
