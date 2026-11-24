# Project: ErisLITE
# Module: undo.py
# Author: Liam Piper-Brandon
# Version: 1.5.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-10-14
# Description: Rapid Response rollback and undo operations.

import hashlib
import json
import os
import re
import secrets
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
from erislite.security.safe_io import (
    open_private_dir,
    read_regular_bytes,
)
from erislite.ui.console import console
from erislite.ui.utils import clear_screen, pause_return


def _format_undo(undo) -> str:
    if isinstance(undo, list):
        return " ".join(str(part) for part in undo)

    if isinstance(undo, dict):
        if undo.get("type") == "restore_file":
            return f"restore {undo.get('source', '?')} → {undo.get('destination', '?')}"

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


def _verify_backup_digest(content: bytes, expected: str) -> tuple[bool, str]:
    """Verify a quarantined file against its recorded SHA-256 digest."""

    if not isinstance(expected, str):
        return False, "Invalid backup SHA-256 metadata"

    if re.fullmatch(r"[0-9a-fA-F]{64}", expected) is None:
        return False, "Invalid backup SHA-256 digest"

    actual = hashlib.sha256(content).hexdigest()

    if actual != expected.lower():
        return False, "Quarantined backup SHA-256 mismatch"

    return True, ""


class RestorePublicationUncertain(OSError):
    """Restoration was published, but durability could not be confirmed."""


def _write_restored_cron_exclusive(
    destination: str,
    content: bytes,
    mode: int,
    owner: tuple[int, int],
) -> None:
    """Stage a complete cron file before publishing it without replacement.

    The temporary file is kept in a private subdirectory so that it is
    not exposed as a top-level cron entry while being written.
    """

    path = Path(destination)
    dir_fd = open_private_dir(path.parent, create=False)

    stage_name = f".erislite-restore-{secrets.token_hex(16)}"
    stage_fd = None
    stage_created = False
    payload_created = False

    try:
        # A unique private directory keeps the incomplete file separate
        # from the cron directory's top-level entries.
        os.mkdir(stage_name, mode=0o700, dir_fd=dir_fd)
        stage_created = True

        stage_fd = os.open(
            stage_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=dir_fd,
        )

        payload_fd = os.open(
            "payload",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=stage_fd,
        )
        payload_created = True

        with os.fdopen(payload_fd, "wb") as restored:
            restored.write(content)
            restored.flush()

            os.fchown(restored.fileno(), owner[0], owner[1])
            os.fchmod(restored.fileno(), mode)
            os.fsync(restored.fileno())

        # Persist the staging directory entry before publication.
        os.fsync(stage_fd)

        # Hard-link publication is atomic and refuses an existing name.
        # The temporary file and destination share the same filesystem.
        os.link(
            "payload",
            path.name,
            src_dir_fd=stage_fd,
            dst_dir_fd=dir_fd,
            follow_symlinks=False,
        )

        # The destination is now published. A failure to synchronize
        # the directory does not mean publication failed.
        try:
            os.fsync(dir_fd)
        except OSError as exc:
            raise RestorePublicationUncertain(
                f"Restoration published at {destination}, "
                f"but directory synchronization failed: {exc}"
            ) from exc

    finally:
        if stage_fd is not None:
            if payload_created:
                try:
                    os.unlink("payload", dir_fd=stage_fd)
                except OSError:
                    pass

            os.close(stage_fd)

        if stage_created:
            try:
                os.rmdir(stage_name, dir_fd=dir_fd)
            except OSError:
                pass

        os.close(dir_fd)


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

    expected_digest = undo.get("sha256")

    if expected_digest is not None:
        valid, reason = _verify_backup_digest(content, expected_digest)

        if not valid:
            return False, reason

    elif str(Path(source).name).endswith(".recovery.json"):
        return False, "Recovery manifest cannot be used as a backup"

    # Restore the job, not the weakness: the world-writable bit that got
    # the file flagged is never put back.
    mode = int(undo.get("mode", 0o644)) & 0o7777 & ~stat.S_IWOTH
    owner = (int(undo.get("uid", 0)), int(undo.get("gid", 0)))

    try:
        _write_restored_cron_exclusive(
            destination,
            content,
            mode,
            owner,
        )

    except FileExistsError:
        return False, f"Refusing to overwrite existing cron file: {destination}"

    except RestorePublicationUncertain as exc:
        return (
            False,
            f"{exc}. Publication occurred, but filesystem durability "
            "is unconfirmed. Inspect the destination before retrying.",
        )

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
        console.print(f"[cyan][{index}][/] {entry['type']} — {_format_undo(entry['undo'])}")

    console.print()

    if not Confirm.ask("[yellow]Run all undo operations?[/]", default=False):
        console.print("[yellow]Undo cancelled.[/]")
        pause_return()
        return

    for entry in undoable:
        success, detail = _execute_undo(entry)

        if success:
            console.print(f"[green]Undone:[/] {_format_undo(entry['undo'])}")
        else:
            console.print(f"[red]Failed:[/] {_format_undo(entry['undo'])} — {detail}")

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
