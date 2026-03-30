# main.py
# ErisLITE entry point.
# Loads the user profile, shows the splash screen, and launches the CLI.

import os

from rich.console import Console

from core.user_profile import load_or_create_profile
from ui.splash import show_splash
from ui.cli import launch_cli

console = Console()

# DEV_MODE controls whether KeyboardInterrupt shows a full traceback (True)
# or a clean exit message (False). Set the ERISLITE_DEV environment variable
# to "1" to enable dev mode without editing this file.
DEV_MODE = os.getenv("ERISLITE_DEV", "0") == "1"


def main():
    profile = load_or_create_profile()
    show_splash(profile)
    launch_cli(profile)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        if DEV_MODE:
            raise
        else:
            console.print("\n[bold red]Interrupted by user. Exiting...[/]")