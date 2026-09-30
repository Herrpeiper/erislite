# Project: ErisLITE
# Module: storage.py
# Author: Liam Piper-Brandon
# Version: 1.4.0
# License: MIT
# Created: 2026-09-26
# Last Updated: 2026-09-30
# Description: Persistent event storage for Odyssey Lite.

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

from erislite.deception.odyssey.events import OdysseyEvent

# parents[2] is the erislite/ package directory, not the repository root.
_PACKAGE_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LOG_DIR = _PACKAGE_ROOT / "data" / "logs" / "odyssey"
DEFAULT_EVENT_LOG = DEFAULT_LOG_DIR / "odyssey_events.jsonl"

_DIRECTORY_MODE = 0o700
_FILE_MODE = 0o600
MAX_LOG_BYTES = 5 * 1024 * 1024
MAX_LOG_BACKUPS = 3

# Every operation after the directory is verified goes through its file
# descriptor. Renaming or swapping the directory path after the check has
# no effect on where ErisLITE reads, writes, renames or deletes.


def _open_log_directory(path: Path) -> int:
    """Create, verify and open the Odyssey log directory.

    Returns a directory file descriptor. The caller must close it.
    """

    if path.is_symlink():
        raise OSError(f"Refusing to use symlinked Odyssey log directory: {path}")

    path.mkdir(parents=True, exist_ok=True, mode=_DIRECTORY_MODE)

    try:
        dir_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except NotADirectoryError as exc:
        raise OSError(f"Odyssey log path is not a directory: {path}") from exc
    except OSError as exc:
        raise OSError(f"Refusing to use Odyssey log directory: {path} ({exc})") from exc

    try:
        info = os.fstat(dir_fd)

        if info.st_uid != os.geteuid():
            raise OSError(
                f"Refusing to use Odyssey log directory owned by uid {info.st_uid}: {path}"
            )

        os.fchmod(dir_fd, _DIRECTORY_MODE)
    except BaseException:
        os.close(dir_fd)
        raise

    return dir_fd


def _lstat_in(dir_fd: int, name: str) -> os.stat_result | None:
    """Return lstat for a name inside the log directory, or None if absent."""

    try:
        return os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _open_event_log(dir_fd: int, name: str):
    """Open the Odyssey event log for secure append."""

    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW
    fd = os.open(name, flags, _FILE_MODE, dir_fd=dir_fd)

    try:
        info = os.fstat(fd)

        if not stat.S_ISREG(info.st_mode):
            raise OSError(f"Refusing to write non-regular Odyssey event log: {name}")

        if info.st_nlink != 1:
            raise OSError(f"Refusing to write hard-linked Odyssey event log: {name}")

        if info.st_uid != os.geteuid():
            raise OSError(
                f"Refusing to write Odyssey event log owned by uid {info.st_uid}: {name}"
            )

        os.fchmod(fd, _FILE_MODE)
        return os.fdopen(fd, "a", encoding="utf-8")
    except BaseException:
        os.close(fd)
        raise


def _rotate_event_log(dir_fd: int, name: str, max_bytes: int) -> None:
    """Rotate the Odyssey event log when it reaches its size limit.

    Rotation only renames and unlinks inside the verified directory. It never
    changes permissions: every log file is created 0600 by _open_event_log,
    and rename keeps that mode. A chmod here would follow a swapped-in symlink.
    """

    current = _lstat_in(dir_fd, name)

    if current is None:
        return

    if not stat.S_ISREG(current.st_mode):
        raise OSError(f"Refusing to rotate non-regular Odyssey event log: {name}")

    if current.st_size < max_bytes:
        return

    for index in range(1, MAX_LOG_BACKUPS + 1):
        backup = f"{name}.{index}"
        info = _lstat_in(dir_fd, backup)

        if info is not None and not stat.S_ISREG(info.st_mode):
            raise OSError(f"Refusing to rotate non-regular Odyssey backup: {backup}")

    oldest = f"{name}.{MAX_LOG_BACKUPS}"

    if _lstat_in(dir_fd, oldest) is not None:
        os.unlink(oldest, dir_fd=dir_fd)

    for index in range(MAX_LOG_BACKUPS - 1, 0, -1):
        source = f"{name}.{index}"

        if _lstat_in(dir_fd, source) is None:
            continue

        os.replace(
            source,
            f"{name}.{index + 1}",
            src_dir_fd=dir_fd,
            dst_dir_fd=dir_fd,
        )

    os.replace(name, f"{name}.1", src_dir_fd=dir_fd, dst_dir_fd=dir_fd)


def append_event(
    event: OdysseyEvent,
    path: Path = DEFAULT_EVENT_LOG,
    max_bytes: int = MAX_LOG_BYTES,
) -> None:
    """Append an Odyssey event to the persistent JSONL event log."""

    dir_fd = _open_log_directory(path.parent)

    try:
        _rotate_event_log(dir_fd, path.name, max_bytes)

        with _open_event_log(dir_fd, path.name) as file:
            json.dump(event.to_dict(), file, sort_keys=True)
            file.write("\n")
    finally:
        os.close(dir_fd)
