# Project: ErisLITE
# Module: import_guard.py
# Author: Liam Piper-Brandon
# Version: 1.3.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-26
# Description: Monitors and validates dynamic imports to prevent unauthorized code execution.

import os
import sys
from pathlib import Path
from typing import List

PROJECT_ROOT = Path(__file__).resolve().parents[2]

SENSITIVE_MODULE_NAMES = {
    "psutil",
    "rich",
    "erislite",
}

SUSPICIOUS_IMPORT_ROOTS = (
    Path("/tmp"),
    Path("/var/tmp"),
    Path("/dev/shm"),
)


def _is_under(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def check_pythonpath() -> List[str]:
    issues = []

    pythonpath = os.environ.get("PYTHONPATH")

    if pythonpath:
        issues.append(
            f"PYTHONPATH is set: {pythonpath}"
        )

    return issues


def check_sys_path() -> List[str]:
    issues = []

    for entry in sys.path:
        if not entry:
            candidate = Path.cwd()
        else:
            candidate = Path(entry)

        try:
            resolved = candidate.resolve()
        except OSError:
            continue

        for suspicious_root in SUSPICIOUS_IMPORT_ROOTS:
            if _is_under(resolved, suspicious_root):
                issues.append(
                    f"Suspicious import path: {resolved}"
                )
                break

    return issues


def check_shadow_files() -> List[str]:
    issues = []

    cwd = Path.cwd().resolve()

    if cwd == PROJECT_ROOT:
        return issues

    for module_name in SENSITIVE_MODULE_NAMES:
        candidates = (
            cwd / f"{module_name}.py",
            cwd / module_name,
        )

        for candidate in candidates:
            if candidate.exists():
                issues.append(
                    f"Potential module shadowing detected: {candidate}"
                )

    return issues


def check_import_environment() -> dict:
    issues = []

    issues.extend(check_pythonpath())
    issues.extend(check_sys_path())
    issues.extend(check_shadow_files())

    return {
        "status": "warning" if issues else "ok",
        "details": issues,
        "tags": ["import_environment_suspicious"] if issues else [],
    }
