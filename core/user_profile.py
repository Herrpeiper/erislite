# Project: ErisLITE
# Module: user_profile.py
# Author: Liam Piper-Brandon
# Version: 0.7
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-03-29
# Description: Manages user_profile.json: creation, locking, and forward-migration of missing fields.

import json
import os
import socket

from pathlib import Path
from rich.console import Console

console = Console()

# Profile lives in data/ alongside logs, integrity, etc.
# Path is resolved relative to this file so it always points to the right
# place regardless of what directory Python is launched from.
_REPO_ROOT   = Path(__file__).resolve().parent.parent
PROFILE_PATH = _REPO_ROOT / "data" / "user_profile.json"

# Schema defaults — add new fields here when the schema changes.
# load_or_create_profile() will automatically backfill them into any
# existing profile that is missing them.
PROFILE_DEFAULTS = {
    "hostname":       None,     # set to socket.gethostname() at creation time
    "segment":        "default",
    "role":           "workstation",
    "analyst_id":     0,
    "edge_firewall":  "unknown",
    "known_users":    [],       # v0.6.0 — suppresses UNRECOGNIZED alerts in snapshots
}


def _unlock(path: Path) -> None:
    try:
        os.chmod(path, 0o644)
    except Exception:
        pass


def _lock(path: Path) -> None:
    try:
        os.chmod(path, 0o444)
    except Exception:
        pass


def _migrate(profile: dict) -> tuple:
    """Backfill any keys missing from older profiles. Returns (profile, changed)."""
    changed = False
    for key, default in PROFILE_DEFAULTS.items():
        if key not in profile:
            profile[key] = default
            changed = True
    return profile, changed


def load_or_create_profile() -> dict:
    # Ensure data/ exists before trying to read or write
    PROFILE_PATH.parent.mkdir(parents=True, exist_ok=True)

    if PROFILE_PATH.exists():
        try:
            with open(PROFILE_PATH) as f:
                profile = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            console.print(f"[red]Warning: could not read user_profile.json ({e}). Using defaults.[/]")
            profile = {}

        profile, changed = _migrate(profile)

        if changed:
            console.print("[yellow]User profile updated with new default fields.[/]")
            _unlock(PROFILE_PATH)
            try:
                with open(PROFILE_PATH, "w") as f:
                    json.dump(profile, f, indent=4)
            finally:
                _lock(PROFILE_PATH)

        return profile

    else:
        profile = {**PROFILE_DEFAULTS, "hostname": socket.gethostname()}

        with open(PROFILE_PATH, "w") as f:
            json.dump(profile, f, indent=4)

        _lock(PROFILE_PATH)

        console.print("[yellow]User profile created at data/user_profile.json and locked (read-only).[/]")
        return profile