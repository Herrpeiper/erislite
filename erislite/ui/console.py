"""
ErisLITE v1.1
Shared Rich console instance.
"""

from rich.console import Console

from erislite.config.theme import ERISLITE_THEME


console = Console(theme=ERISLITE_THEME)