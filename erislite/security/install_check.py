# Project: ErisLITE
# Module: install_check.py
# Author: Liam Piper-Brandon
# Version: 1.5.0
# License: MIT
# Created: 2026-10-12
# Description: Refuses root execution from an install tree other users can modify.

"""
Install tree ownership check.

When root runs ErisLITE, every file Python imports from the install tree
runs as root. If an unprivileged account owns or can write any of that
code, or any directory above it, a compromise of that account becomes a
root compromise the next time an analyst runs ErisLITE with sudo.

This module uses the standard library only so it can run before any
third-party import.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import List, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Paths under the project root that root reads or executes at runtime.
RUNTIME_PATHS = ("main.py", "erislite", "data")

MAX_REPORTED = 15


def _describe(path: Path, info: os.stat_result, trusted_uids) -> Optional[str]:
    if info.st_uid not in trusted_uids:
        return f"{path} is owned by uid {info.st_uid}"

    if stat.S_ISLNK(info.st_mode):
        return None

    writable = info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)

    if not writable:
        return None

    if stat.S_ISDIR(info.st_mode) and info.st_mode & stat.S_ISVTX:
        # A sticky, world-writable directory such as /tmp: others can add
        # entries but cannot rename or delete entries they do not own.
        return None

    return f"{path} is writable by group or other users (mode {info.st_mode & 0o7777:o})"


def _ancestor_issues(root: Path, trusted_uids) -> List[str]:
    issues = []

    for directory in reversed(root.parents):
        try:
            info = os.stat(directory)
        except OSError as exc:
            issues.append(f"{directory}: cannot inspect ({exc})")
            continue

        issue = _describe(directory, info, trusted_uids)

        if issue:
            issues.append(issue)

    return issues


def _tree_issues(root: Path, trusted_uids) -> List[str]:
    issues = []

    def check(path: Path) -> None:
        try:
            info = os.lstat(path)
        except OSError as exc:
            issues.append(f"{path}: cannot inspect ({exc})")
            return

        issue = _describe(path, info, trusted_uids)

        if issue:
            issues.append(issue)

    check(root)

    for name in RUNTIME_PATHS:
        start = root / name

        if not os.path.lexists(start):
            continue

        check(start)

        if not start.is_dir() or start.is_symlink():
            continue

        for current, dirs, files in os.walk(start, followlinks=False):
            for entry in dirs + files:
                check(Path(current) / entry)

                if len(issues) > MAX_REPORTED:
                    return issues

    return issues


def find_unsafe_install_paths(root: Path = PROJECT_ROOT, euid: Optional[int] = None) -> List[str]:
    """Return reasons the install tree is unsafe for the given effective UID.

    Only root needs this protection. For any other user the list is empty.
    """

    if euid is None:
        euid = os.geteuid()

    if euid != 0:
        return []

    trusted_uids = {0}
    root = Path(os.path.abspath(root))

    issues = _ancestor_issues(root, trusted_uids) + _tree_issues(root, trusted_uids)
    return issues[: MAX_REPORTED + 1]


def remediation(root: Path = PROJECT_ROOT) -> str:
    return (
        f"Make the install root-owned and not writable by other users:\n"
        f"  sudo chown -R root:root {root}\n"
        f"  sudo chmod -R go-w {root}\n"
        f"Or reinstall under /opt as described in the README. If the install sits "
        f"under a user's home directory, move it: the home directory itself is "
        f"user-owned."
    )
