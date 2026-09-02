# Project: ErisLITE
# Module: theme.py
# Author: Liam Piper-Brandon
# Version: 1.1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-02
# Description: Shared ErisLITE terminal theme and presentation constants.

"""
ErisLITE v1.1
Centralized Rich theme and UI style definitions.
"""

from rich.theme import Theme


ERISLITE_THEME = Theme(
    {
        # General
        "primary": "bold cyan",
        "secondary": "cyan",
        "muted": "grey62",
        "dim": "grey50",
        # Status
        "success": "green",
        "info": "cyan",
        "warning": "yellow",
        "danger": "red",
        "critical": "bold red",
        # UI
        "header": "bold cyan",
        "title": "bold white",
        "menu.key": "bold cyan",
        "menu.text": "white",
        # Security findings
        "finding.ok": "green",
        "finding.info": "cyan",
        "finding.warning": "yellow",
        "finding.error": "red",
        "finding.critical": "bold red",
    }
)


STATUS_ICONS = {
    "ok": "✔",
    "info": "ℹ",
    "warning": "⚠",
    "error": "✖",
    "critical": "✖",
    "unsupported": "—",
    "unknown": "?",
}


STATUS_LABELS = {
    "ok": "OK",
    "info": "INFO",
    "warning": "WARNING",
    "error": "ERROR",
    "critical": "CRITICAL",
    "unsupported": "UNSUPPORTED",
    "unknown": "UNKNOWN",
}


STATUS_STYLES = {
    "ok": "finding.ok",
    "info": "finding.info",
    "warning": "finding.warning",
    "error": "finding.error",
    "critical": "finding.critical",
    "unsupported": "muted",
    "unknown": "muted",
}
