# Project: ErisLITE
# Module: main.py
# Author: Liam Piper-Brandon
# Version: 1.2.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-11
# Description: ErisLITE entry point — initializes user profile and launches the CLI.

import os

from erislite.security.import_guard import check_import_environment

# Import guard intentionally runs before third-party imports.
# Do not move below Rich or other external dependencies.
IMPORT_STATUS = check_import_environment()

from rich.console import Console

from erislite.accounts.profile import load_or_create_profile
from erislite.ui.cli import launch_cli
from erislite.ui.splash import show_splash

console = Console()

# DEV_MODE controls whether KeyboardInterrupt shows a full traceback (True)
# or a clean exit message (False). Set the ERISLITE_DEV environment variable
# to "1" to enable dev mode without editing this file.
DEV_MODE = os.getenv("ERISLITE_DEV", "0") == "1"


def _show_import_warning() -> None:
    if IMPORT_STATUS["status"] == "ok":
        return

    console.print(
        "\n[bold yellow]IMPORT ENVIRONMENT WARNING[/]"
    )

    for detail in IMPORT_STATUS["details"]:
        console.print(
            f"[yellow]•[/] {detail}"
        )

    console.print(
        "[dim]ErisLITE will continue, but the Python "
        "import environment should be reviewed.[/]\n"
    )


def main():
    _show_import_warning()

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
            console.print(
                "\n[bold red]Interrupted by user. Exiting...[/]"
            )
