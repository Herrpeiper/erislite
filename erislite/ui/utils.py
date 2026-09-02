# Project: ErisLITE
# Module: utils.py
# Author: Liam Piper-Brandon
# Version: 1.1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-02
# Description: Shared UI utilities for screen control, headers, prompts, and platform detection.

import json
import os
import platform
from datetime import datetime

from rich import box
from rich.panel import Panel
from rich.text import Text

from erislite.config.settings import APP_NAME, APP_VERSION
from erislite.ui.console import console


def get_os() -> str:
    """
    Return Windows, Linux, or Other.
    """
    system = platform.system()

    if system == "Windows":
        return "Windows"

    if system == "Linux":
        return "Linux"

    return "Other"


def clear_screen() -> None:
    os.system(
        "cls"
        if get_os() == "Windows"
        else "clear"
    )


def show_header(
    title: str = "ERISLITE",
    description: str | None = None,
) -> None:
    """
    Legacy-compatible shared header.

    Newer modules may define their own page-specific header,
    but older modules can continue calling show_header().
    """
    body = (
        Text.from_markup(f"[dim]{description}[/]")
        if description
        else Text("")
    )

    console.print(
        Panel(
            body,
            title=f"[bold cyan]{title}[/]",
            subtitle=f"[dim cyan]{APP_NAME} v{APP_VERSION}[/]",
            border_style="cyan",
            box=box.SQUARE,
            padding=(0, 1),
        )
    )

    console.print()


def pause_return(centered: bool = False) -> None:
    """
    Pause before returning to the previous menu.

    `centered` is retained for compatibility with older callers,
    but the prompt now uses the standard ErisLITE layout.
    """
    console.input(
        "\n[dim cyan][ENTER] Return to menu[/]"
    )


def export_json_log(
    data,
    prefix: str = "log",
    folder: str = "logs",
) -> str:
    """
    Export structured data to a timestamped JSON file.
    """
    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    os.makedirs(
        folder,
        exist_ok=True,
    )

    filename = f"{prefix}_{timestamp}.json"
    filepath = os.path.join(
        folder,
        filename,
    )

    with open(
        filepath,
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            data,
            file,
            indent=2,
        )

    return filepath