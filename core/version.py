# Project: ErisLITE
# Module: version.py
# Author: Liam Piper-Brandon
# License: MIT
# Created: 2026-03-29
# Description:
#   Single source of truth for the application version and build metadata.
#   Import VERSION and BUILD_DATE from here instead of hardcoding strings
#   in individual UI modules — this ensures splash.py, help_menu.py, and
#   any future modules always display a consistent version number.

VERSION = "0.6.0"
BUILD_DATE = "29MAR26"
VERSION_LABEL = f"ErisLite v{VERSION} - Beta Release"
