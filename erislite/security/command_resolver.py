# Project: ErisLITE
# Module: command_resolver.py
# Author: Liam Piper-Brandon
# Version: 1.3.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-26
# Description: Trusted command resolution and executable path validation.

"""Trusted system-command resolution for ErisLITE."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable

TRUSTED_COMMAND_DIRS = (
    Path("/usr/sbin"),
    Path("/usr/bin"),
    Path("/sbin"),
    Path("/bin"),
)


class CommandResolutionError(RuntimeError):
    """Raised when a command cannot be resolved from a trusted location."""


def resolve_command(
    command: str,
    trusted_dirs: Iterable[Path] = TRUSTED_COMMAND_DIRS,
) -> str:
    """
    Resolve a command only from explicitly trusted system directories.

    The caller's PATH is intentionally ignored.
    """
    if not command:
        raise CommandResolutionError("Command name cannot be empty")

    if os.path.sep in command:
        raise CommandResolutionError(
            f"Command must be a bare executable name: {command!r}"
        )

    for directory in trusted_dirs:
        candidate = directory / command

        if not candidate.is_file():
            continue

        if not os.access(candidate, os.X_OK):
            continue

        return str(candidate)

    raise CommandResolutionError(
        f"Trusted executable not found: {command}"
    )


def command_available(command: str) -> bool:
    """Return True when a command exists in a trusted system directory."""
    try:
        resolve_command(command)
    except CommandResolutionError:
        return False

    return True