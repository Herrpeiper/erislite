# Project: ErisLITE
# Module: console.py
# Author: Liam Piper-Brandon
# Version: 1.1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-02
# Description: Shared Rich console instance for ErisLITE terminal output.

"""
ErisLITE v1.1
Shared Rich console instance.
"""

from rich.console import Console

from erislite.config.theme import ERISLITE_THEME


console = Console(theme=ERISLITE_THEME)
