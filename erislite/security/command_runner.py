# Project: ErisLITE
# Module: command_runner.py
# Author: Liam Piper-Brandon
# Version: 1.5.0
# License: MIT
# Created: 2026-10-09
# Description: Shared command execution helper for ErisLITE modules.

import subprocess
from typing import Optional, Sequence

from erislite.config.settings import DEFAULT_COMMAND_TIMEOUT
from erislite.security.command_resolver import resolve_command


def run_command(
    command: Sequence[str],
    *,
    timeout: Optional[float] = None,
    check: bool = False,
) -> subprocess.CompletedProcess:
    if not command:
        raise ValueError("Command cannot be empty")

    resolved = [
        resolve_command(command[0]),
        *command[1:],
    ]

    return subprocess.run(
        resolved,
        capture_output=True,
        text=True,
        timeout=(
            DEFAULT_COMMAND_TIMEOUT
            if timeout is None
            else timeout
        ),
        check=check,
    )