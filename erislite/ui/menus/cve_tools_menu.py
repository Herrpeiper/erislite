# Project: ErisLITE
# Module: cve_tools_menu.py
# Author: Liam Piper-Brandon
# Version: 1.1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-02
# Description: CVE tools launcher menu.

from erislite.vulnerability import cve_tools


def launch_cve_tools_menu() -> None:
    cve_tools.run_cve_tool()
