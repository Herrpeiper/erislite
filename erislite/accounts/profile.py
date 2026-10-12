# Project: ErisLITE
# Module: profile.py
# Author: Liam Piper-Brandon
# Version: 1.5.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-10-12
# Description: Manages user profile creation, locking, and migration.

import json
import socket
from pathlib import Path

from rich.console import Console

from erislite.security.safe_io import write_private_json

console = Console()

# Profile lives in data/ alongside logs, integrity, etc.
# Path is resolved relative to this file so it always points to the right
# place regardless of what directory Python is launched from.
_REPO_ROOT = Path(__file__).resolve().parent.parent
PROFILE_PATH = _REPO_ROOT / "data" / "user_profile.json"

# Schema defaults — add new fields here when the schema changes.
# load_or_create_profile() will automatically backfill them into any
# existing profile that is missing them.
PROFILE_DEFAULTS = {
    "hostname": None,  # set to socket.gethostname() at creation time
    "segment": "default",
    "role": "workstation",
    "analyst_id": None,
    "edge_firewall": "unknown",
    "known_users": [],  # v0.6.0 — suppresses UNRECOGNIZED alerts in snapshots
}


# The profile is written read-only (0444) to discourage casual edits.
# Writes replace the file through a rename, so no unlock step is needed.
_PROFILE_MODE = 0o444


def _save(profile: dict) -> None:
    write_private_json(PROFILE_PATH, profile, mode=_PROFILE_MODE, indent=4)


def _migrate(profile: dict) -> tuple:
    """Backfill missing keys and normalize legacy profile values."""
    changed = False

    for key, default in PROFILE_DEFAULTS.items():
        if key not in profile:
            profile[key] = default
            changed = True

    # Legacy analyst_id used 0 to mean "unset".
    if profile.get("analyst_id") == 0:
        profile["analyst_id"] = None
        changed = True

    return profile, changed


def load_or_create_profile() -> dict:
    if PROFILE_PATH.exists():
        try:
            with open(PROFILE_PATH) as f:
                profile = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            console.print(
                f"[red]Warning: could not read user_profile.json ({e}). Using defaults.[/]"
            )
            profile = {}

        profile, changed = _migrate(profile)

        current_hostname = socket.gethostname()

        if profile.get("hostname") != current_hostname:
            profile["hostname"] = current_hostname
            changed = True

        if changed:
            console.print("[yellow]User profile updated with current system information.[/]")
            try:
                _save(profile)
            except OSError as exc:
                console.print(f"[red]Warning: could not save user profile ({exc}).[/]")

        return profile

    else:
        profile = {**PROFILE_DEFAULTS, "hostname": socket.gethostname()}

        try:
            _save(profile)
        except OSError as exc:
            console.print(f"[red]Warning: could not save user profile ({exc}).[/]")
            return profile

        console.print(
            f"[yellow]User profile created at {PROFILE_PATH} (read-only).[/]"
        )
        return profile
