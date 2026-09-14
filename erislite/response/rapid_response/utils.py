# Project: ErisLITE
# Module: utils.py
# Author: Liam Piper-Brandon
# Version: 1.2.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-11
# Description: Shared Rapid Response utility functions and runtime paths.

from __future__ import annotations

import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Tuple

from erislite.security.command_resolver import (
    CommandResolutionError,
    resolve_command,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
LOG_DIR = REPO_ROOT / "data" / "logs" / "rapid_response"


def have(cmd: str) -> bool:
    try:
        resolve_command(cmd)
    except CommandResolutionError:
        return False

    return True


def run_cmd(args: List[str], timeout: int = 10) -> Tuple[int, str, str]:
    if not args:
        return 1, "", "No command provided"

    try:
        resolved = [resolve_command(args[0]), *args[1:]]

        result = subprocess.run(
            resolved,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        return (
            result.returncode,
            result.stdout.strip(),
            result.stderr.strip(),
        )

    except CommandResolutionError as e:
        return 1, "", str(e)

    except subprocess.TimeoutExpired:
        return 1, "", f"Command timed out after {timeout}s"

    except Exception as e:
        return 1, "", str(e)


def now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log_path() -> Path:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return LOG_DIR / f"rapid_response_{timestamp}.json"
