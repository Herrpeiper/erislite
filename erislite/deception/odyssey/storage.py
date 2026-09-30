# Project: ErisLITE
# Module: storage.py
# Author: Liam Piper-Brandon
# Version: 1.4.0
# License: MIT
# Created: 2026-09-26
# Last Updated: 2026-09-29
# Description: Persistent event storage for Odyssey Lite.

from __future__ import annotations

import json
import os
from pathlib import Path

from erislite.deception.odyssey.events import OdysseyEvent

_REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LOG_DIR = _REPO_ROOT / "data" / "logs" / "odyssey"
DEFAULT_EVENT_LOG = DEFAULT_LOG_DIR / "odyssey_events.jsonl"

_DIRECTORY_MODE = 0o700
_FILE_MODE = 0o600
MAX_LOG_BYTES = 5 * 1024 * 1024
MAX_LOG_BACKUPS = 3


def _prepare_log_directory(path: Path) -> None:
    """Create and secure the Odyssey event log directory."""

    if path.is_symlink():
        raise OSError(
            f"Refusing to use symlinked Odyssey log directory: {path}"
        )

    path.mkdir(
        parents=True,
        exist_ok=True,
        mode=_DIRECTORY_MODE,
    )

    if path.is_symlink():
        raise OSError(
            f"Refusing to use symlinked Odyssey log directory: {path}"
        )

    if not path.is_dir():
        raise OSError(
            f"Odyssey log path is not a directory: {path}"
        )

    path.chmod(_DIRECTORY_MODE)


def _open_event_log(path: Path):
    """Open an Odyssey event log for secure append."""

    flags = (
        os.O_WRONLY
        | os.O_APPEND
        | os.O_CREAT
        | os.O_NOFOLLOW
    )

    fd = os.open(
        path,
        flags,
        _FILE_MODE,
    )

    try:
        os.fchmod(fd, _FILE_MODE)
        return os.fdopen(
            fd,
            "a",
            encoding="utf-8",
        )
    except Exception:
        os.close(fd)
        raise


def _rotate_event_log(
    path: Path,
    max_bytes: int,
) -> None:
    """Rotate the Odyssey event log when it reaches its size limit."""

    if not path.exists():
        return

    if path.is_symlink():
        raise OSError(
            f"Refusing to rotate symlinked Odyssey event log: {path}"
        )

    if path.stat().st_size < max_bytes:
        return

    oldest = path.with_name(
        f"{path.name}.{MAX_LOG_BACKUPS}"
    )

    if oldest.exists():
        if oldest.is_symlink():
            raise OSError(
                f"Refusing to replace symlinked Odyssey backup: {oldest}"
            )
        oldest.unlink()

    for index in range(MAX_LOG_BACKUPS - 1, 0, -1):
        source = path.with_name(f"{path.name}.{index}")

        if not source.exists():
            continue

        if source.is_symlink():
            raise OSError(
                f"Refusing to rotate symlinked Odyssey backup: {source}"
            )

        destination = path.with_name(
            f"{path.name}.{index + 1}"
        )

        source.replace(destination)
        destination.chmod(_FILE_MODE)

    first_backup = path.with_name(f"{path.name}.1")
    path.replace(first_backup)
    first_backup.chmod(_FILE_MODE)
    

def append_event(
    event: OdysseyEvent,
    path: Path = DEFAULT_EVENT_LOG,
    max_bytes: int = MAX_LOG_BYTES,
) -> None:
    """Append an Odyssey event to the persistent JSONL event log."""

    _prepare_log_directory(path.parent)
    _rotate_event_log(path, max_bytes)

    with _open_event_log(path) as file:
        json.dump(
            event.to_dict(),
            file,
            sort_keys=True,
        )
        file.write("\n")
