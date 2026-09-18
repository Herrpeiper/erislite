# Project: ErisLITE
# Module: shell_console.py
# Author: Liam Piper-Brandon
# Version: 1.3.0
# License: MIT
# Created: 2026-09-18
# Last Updated: 2026-09-18
# Description: Launches an interactive system shell from ErisLITE.

import getpass
import os
import pwd
import shutil
import subprocess
from pathlib import Path

from rich import box
from rich.panel import Panel
from rich.table import Table

from erislite.config.settings import APP_NAME, APP_VERSION
from erislite.ui.console import console
from erislite.ui.utils import clear_screen


def resolve_user_shell() -> str | None:
    """
    Resolve an available interactive shell.

    Resolution order:
    1. SHELL environment variable
    2. Current user's passwd entry
    3. bash
    4. sh
    """
    candidates = []

    environment_shell = os.environ.get("SHELL")
    if environment_shell:
        candidates.append(environment_shell)

    try:
        account_shell = pwd.getpwuid(os.geteuid()).pw_shell
        if account_shell:
            candidates.append(account_shell)
    except (KeyError, OSError):
        pass

    for fallback in ("bash", "sh"):
        resolved = shutil.which(fallback)
        if resolved:
            candidates.append(resolved)

    for candidate in candidates:
        path = Path(candidate)

        if path.is_file() and os.access(path, os.X_OK):
            return str(path)

    return None


def get_privilege_label() -> str:
    if os.geteuid() == 0:
        return "[bold red]ROOT ACCESS[/]"

    return "[green]User Session[/]"


def show_shell_header(
    profile: dict,
    shell_path: str,
) -> None:
    hostname = profile.get("hostname", "unknown-host")
    username = getpass.getuser()

    details = Table(
        show_header=False,
        box=None,
        padding=(0, 1),
        collapse_padding=True,
    )
    details.add_column(style="dim", no_wrap=True)
    details.add_column(style="white")

    details.add_row("Host", str(hostname))
    details.add_row("User", username)
    details.add_row("Shell", shell_path)
    details.add_row("Privilege", get_privilege_label())
    details.add_row(
        "Return",
        "Type [bold cyan]exit[/] or press [bold cyan]Ctrl+D[/]",
    )

    console.print(
        Panel(
            details,
            title=f"[bold cyan]{APP_NAME.upper()} SHELL CONSOLE[/]",
            subtitle=f"[dim cyan]{APP_NAME} v{APP_VERSION}[/]",
            border_style="cyan",
            box=box.SQUARE,
            padding=(0, 1),
        )
    )
    console.print()


def launch_shell_console(profile: dict) -> None:
    """
    Launch the user's interactive shell with the current terminal attached.

    The shell inherits ErisLITE's current user, environment, working
    directory, and privileges. Exiting the shell returns to ErisLITE.
    """
    clear_screen()

    shell_path = resolve_user_shell()

    if shell_path is None:
        console.print(
            "[bold red]Unable to locate an executable system shell.[/]"
        )
        console.input("\n[dim cyan][ENTER] Return to menu[/]")
        return

    show_shell_header(
        profile,
        shell_path,
    )

    try:
        subprocess.run(
            [shell_path],
            check=False,
        )
    except FileNotFoundError:
        console.print(
            f"\n[bold red]Shell not found:[/] [white]{shell_path}[/]"
        )
        console.input("\n[dim cyan][ENTER] Return to menu[/]")
    except PermissionError:
        console.print(
            f"\n[bold red]Shell is not executable:[/] [white]{shell_path}[/]"
        )
        console.input("\n[dim cyan][ENTER] Return to menu[/]")
    except KeyboardInterrupt:
        console.print(
            "\n[yellow]Shell console interrupted. Returning to ErisLITE.[/]"
        )