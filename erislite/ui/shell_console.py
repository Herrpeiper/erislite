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
import subprocess

from rich import box
from rich.panel import Panel
from rich.table import Table

from erislite.config.settings import APP_NAME, APP_VERSION
from erislite.security.command_resolver import (
    CommandResolutionError,
    resolve_command,
)
from erislite.ui.console import console
from erislite.ui.utils import clear_screen


def resolve_user_shell() -> str | None:
    """
    Resolve a trusted interactive shell.

    Environment variables and PATH-based shell discovery are intentionally
    not trusted because ErisLITE may be running on a compromised host.
    """
    for shell in ("bash", "sh"):
        try:
            return resolve_command(shell)
        except CommandResolutionError:
            continue

    return None


def build_shell_environment() -> dict[str, str]:
    """
    Build a reduced environment for the interactive shell.

    Remove variables that can alter executable loading, shell startup,
    command execution, or prompt behavior.
    """
    env = os.environ.copy()

    unsafe_variables = {
        "BASH_ENV",
        "ENV",
        "PROMPT_COMMAND",
        "PS1",
        "PS2",
        "PS4",
        "CDPATH",
        "GLOBIGNORE",
        "IFS",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "PYTHONPATH",
        "PYTHONHOME",
    }

    for name in unsafe_variables:
        env.pop(name, None)

    env["PATH"] = (
        "/usr/local/sbin:"
        "/usr/local/bin:"
        "/usr/sbin:"
        "/usr/bin:"
        "/sbin:"
        "/bin"
    )

    return env


def build_shell_command(shell_path: str) -> list[str]:
    """
    Build a shell command that avoids user-controlled startup files
    where supported.
    """
    shell_name = os.path.basename(shell_path)

    if shell_name == "bash":
        return [
            shell_path,
            "--noprofile",
            "--norc",
        ]

    return [shell_path]


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
        shell_command = build_shell_command(shell_path)
        shell_environment = build_shell_environment()

        subprocess.run(
            shell_command,
            check=False,
            env=shell_environment,
        )
    except OSError as exc:
        console.print(
            f"\n[bold red]Unable to launch shell:[/] "
            f"[white]{shell_path}[/]\n"
            f"[dim]{exc}[/]"
        )
        console.input("\n[dim cyan][ENTER] Return to menu[/]")
    except KeyboardInterrupt:
        console.print(
            "\n[yellow]Shell console interrupted. Returning to ErisLITE.[/]"
        )