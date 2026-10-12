# Project: ErisLITE
# Module: main.py
# Author: Liam Piper-Brandon
# Version: 1.5.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-10-12
# Description: ErisLITE entry point — verifies the runtime environment and launches the CLI.

import argparse
import os
import sys

from erislite.security.import_guard import check_import_environment
from erislite.security.install_check import find_unsafe_install_paths, remediation

# Both checks use the standard library only and intentionally run before
# third-party and application imports. Do not move the delayed imports
# above them.
IMPORT_STATUS = check_import_environment()
INSTALL_ISSUES = find_unsafe_install_paths()

from rich.console import Console  # noqa: E402

from erislite.accounts.profile import load_or_create_profile  # noqa: E402
from erislite.ui.cli import launch_cli  # noqa: E402
from erislite.ui.splash import show_splash  # noqa: E402

console = Console()

# DEV_MODE controls whether KeyboardInterrupt shows a full traceback (True)
# or a clean exit message (False). Set the ERISLITE_DEV environment variable
# to "1" to enable dev mode without editing this file.
DEV_MODE = os.getenv("ERISLITE_DEV", "0") == "1"

UNSAFE_FLAG = "--allow-unsafe-install"


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="erislite",
        description="ErisLITE Linux security monitoring and triage toolkit.",
    )
    parser.add_argument(
        UNSAFE_FLAG,
        action="store_true",
        help=(
            "run as root even though the install tree or Python import path can be "
            "modified by other users"
        ),
    )
    return parser.parse_args(argv)


def _show_import_warning() -> None:
    if IMPORT_STATUS["status"] == "ok":
        return

    console.print("\n[bold yellow]IMPORT ENVIRONMENT WARNING[/]")

    for detail in IMPORT_STATUS["details"]:
        console.print(f"[yellow]•[/] {detail}")

    console.print(
        "[dim]ErisLITE will continue, but the Python import environment should be reviewed.[/]\n"
    )


def check_root_safety(allow_unsafe: bool, euid=None) -> bool:
    """Return True when it is safe to continue.

    As root, an install or import path another user can modify turns that
    user's compromise into root. Refuse unless the operator overrides it.
    """

    if euid is None:
        euid = os.geteuid()

    if euid != 0:
        _show_import_warning()
        return True

    problems = list(INSTALL_ISSUES)

    if IMPORT_STATUS["status"] != "ok":
        problems.extend(IMPORT_STATUS["details"])

    if not problems:
        return True

    title = "UNSAFE INSTALL OVERRIDDEN" if allow_unsafe else "REFUSING TO RUN AS ROOT"
    console.print(f"\n[bold red]{title}[/]")
    console.print(
        "[white]Another account can modify code or imports that ErisLITE would run as root:[/]"
    )

    for problem in problems:
        console.print(f"[red]•[/] {problem}")

    if allow_unsafe:
        console.print(f"[yellow]Continuing because {UNSAFE_FLAG} was given.[/]\n")
        return True

    console.print(f"\n[dim]{remediation()}[/]")
    console.print(f"[dim]To accept the risk for this run, add {UNSAFE_FLAG}.[/]\n")
    return False


def main(argv=None) -> int:
    args = parse_args(argv)

    if not check_root_safety(args.allow_unsafe_install):
        return 1

    profile = load_or_create_profile()
    show_splash(profile)
    launch_cli(profile)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        if DEV_MODE:
            raise
        console.print("\n[bold red]Interrupted by user. Exiting...[/]")
