# Project: ErisLITE
# Module: install_check.py
# Author: Liam Piper-Brandon
# Version: 1.5.0
# License: MIT
# Created: 2026-10-12
# Last Updated: 2026-10-14
# Description: Validates install-tree ownership and permissions before privileged use.

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

import grp
import os
import pwd
import stat
from pathlib import Path
from typing import List, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Paths under the project root that root reads or executes at runtime.
RUNTIME_PATHS = ("main.py", "erislite", "data")

MAX_REPORTED = 15


def _group_has_untrusted_members(gid: int, trusted_uids) -> bool:
    """Return True when an account outside trusted_uids belongs to the group.

    Debian ships /usr/local/lib/pythonX.Y/dist-packages group-writable by
    staff. That is only a risk if someone is actually in the group.
    """

    trusted_names = set()

    for uid in trusted_uids:
        try:
            trusted_names.add(pwd.getpwuid(uid).pw_name)
        except KeyError:
            continue

    try:
        members = set(grp.getgrgid(gid).gr_mem)
    except KeyError:
        # An unnamed group cannot be audited, so treat it as unsafe.
        return True

    if members - trusted_names:
        return True

    try:
        accounts = pwd.getpwall()
    except Exception:
        return True

    return any(account.pw_gid == gid and account.pw_uid not in trusted_uids for account in accounts)


def _describe(path: Path, info: os.stat_result, trusted_uids) -> Optional[str]:
    if info.st_uid not in trusted_uids:
        return f"{path} is owned by uid {info.st_uid}"

    if stat.S_ISLNK(info.st_mode):
        return None

    other_writable = info.st_mode & stat.S_IWOTH
    group_writable = info.st_mode & stat.S_IWGRP and _group_has_untrusted_members(
        info.st_gid, trusted_uids
    )

    if not (other_writable or group_writable):
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

        if stat.S_ISLNK(info.st_mode):
            try:
                target = path.resolve(strict=True)
                target_info = os.stat(target)
            except OSError as exc:
                issues.append(f"{path}: cannot resolve symlink target ({exc})")
                return

            target_issue = _describe(target, target_info, trusted_uids)

            if target_issue:
                issues.append(f"{path} -> {target}: {target_issue}")

            for ancestor_issue in _ancestor_issues(target, trusted_uids):
                issues.append(f"{path} target path is unsafe: {ancestor_issue}")

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
