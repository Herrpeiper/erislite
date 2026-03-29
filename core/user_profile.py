# Project: ErisLITE
# Module: user_profile.py
# Author: Liam Piper-Brandon
# Version: 0.5
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-03-17
# Description:
#   This module manages the user profile, which includes information about the current system and user.
#   The profile is stored in a JSON file and is locked to prevent modifications after creation.

import json, socket, os

from pathlib import Path

# Load or create the user profile
def load_or_create_profile():
    profile_path = Path("user_profile.json")

    if profile_path.exists():
        with open(profile_path) as f:
            return json.load(f)
    else:
        profile = {
            "hostname": socket.gethostname(),
            "segment": "default",
            "role": "workstation",
            "analyst_id": 0,
            "edge_firewall": "unknown"
        }

        with open(profile_path, "w") as f:
            json.dump(profile, f, indent=4)

        # Lock the file (read-only for everyone)
        os.chmod(profile_path, 0o444)

        print("[yellow]User profile created and locked (read-only).[/]")
        return profile
