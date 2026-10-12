# Project: ErisLITE
# Module: safe_io.py
# Author: Liam Piper-Brandon
# Version: 1.5.0
# License: MIT
# Created: 2026-10-12
# Description: Symlink-safe private file writes for data ErisLITE creates as root.

"""
Symlink-safe file writes.

ErisLITE usually runs as root and writes logs, baselines and quarantined
files. A plain open() follows symlinks at every path component, so anyone
who can write to a parent directory can redirect a root write into
/etc/cron.d or similar.

These helpers walk the path one component at a time from "/" with
O_NOFOLLOW, create missing directories with mode 0700, and write through a
temporary file that is renamed into place. The rename replaces a name, it
never writes into an existing inode, so a planted symlink or hard link at
the destination cannot redirect the write.

Symlinks are only followed when they are owned by root or the running user,
because no other user can create one. This keeps system layouts such as
/home -> /var/home working.
"""

from __future__ import annotations

import json
import os
import secrets
import stat
from pathlib import Path
from typing import Any, List, Optional, Tuple, Union

PathLike = Union[str, Path]

DIRECTORY_MODE = 0o700
FILE_MODE = 0o600
_MAX_SYMLINK_HOPS = 40


class UnsafePathError(OSError):
    """Raised when a path cannot be written without following an untrusted link."""


def _trusted_owner(uid: int) -> bool:
    return uid in (0, os.geteuid())


def open_private_dir(path: PathLike, create: bool = True) -> int:
    """Open a directory without following untrusted symlinks.

    Missing directories are created with mode 0700 when create is True.
    Returns a directory file descriptor. The caller must close it.
    """

    pending: List[str] = list(Path(os.path.abspath(path)).parts[1:])
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    hops = 0

    try:
        while pending:
            name = pending.pop(0)

            if name in ("", "."):
                continue

            if name == "..":
                parent = os.open("..", flags, dir_fd=fd)
                os.close(fd)
                fd = parent
                continue

            try:
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(name, DIRECTORY_MODE, dir_fd=fd)
                except FileExistsError:
                    pass
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)

            if stat.S_ISLNK(info.st_mode):
                if not _trusted_owner(info.st_uid):
                    raise UnsafePathError(
                        f"Refusing to follow symlink owned by uid {info.st_uid}: "
                        f"{name} in {path}"
                    )

                hops += 1

                if hops > _MAX_SYMLINK_HOPS:
                    raise UnsafePathError(f"Too many symlinks resolving {path}")

                target = os.readlink(name, dir_fd=fd)

                if os.path.isabs(target):
                    os.close(fd)
                    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)

                pending[:0] = [part for part in target.split("/") if part]
                continue

            try:
                child = os.open(name, flags, dir_fd=fd)
            except OSError as exc:
                raise UnsafePathError(f"Refusing to use path component {name!r} in {path}: {exc}")

            os.close(fd)
            fd = child

        return fd
    except BaseException:
        os.close(fd)
        raise


def write_private_bytes(
    path: PathLike,
    data: bytes,
    mode: int = FILE_MODE,
    owner: Optional[Tuple[int, int]] = None,
    create_dirs: bool = True,
) -> Path:
    """Atomically write data to path. Returns the path.

    The file is created 0600 and only given its final mode and owner after
    the data is written, before it is renamed into place.
    """

    path = Path(path)
    dir_fd = open_private_dir(path.parent, create=create_dirs)
    temp_name = f".{path.name}.{secrets.token_hex(6)}.tmp"

    try:
        fd = os.open(
            temp_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            FILE_MODE,
            dir_fd=dir_fd,
        )

        try:
            with os.fdopen(fd, "wb") as file:
                file.write(data)
                file.flush()

                if owner is not None:
                    os.fchown(file.fileno(), owner[0], owner[1])

                os.fchmod(file.fileno(), mode)
                os.fsync(file.fileno())

            os.replace(temp_name, path.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        except BaseException:
            try:
                os.unlink(temp_name, dir_fd=dir_fd)
            except OSError:
                pass
            raise
    finally:
        os.close(dir_fd)

    return path


def write_private_text(path: PathLike, text: str) -> Path:
    return write_private_bytes(path, text.encode("utf-8"))


def write_private_json(path: PathLike, data: Any, **dump_kwargs: Any) -> Path:
    dump_kwargs.setdefault("indent", 2)
    return write_private_text(path, json.dumps(data, **dump_kwargs))


def read_regular_bytes(path: PathLike) -> bytes:
    """Read a regular file without following untrusted symlinks."""

    path = Path(path)
    dir_fd = open_private_dir(path.parent, create=False)

    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)
    finally:
        os.close(dir_fd)

    with os.fdopen(fd, "rb") as file:
        if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
            raise UnsafePathError(f"Refusing to read non-regular file: {path}")
        return file.read()
