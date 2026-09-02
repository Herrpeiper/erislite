# Project: ErisLITE
# Module: logging.py
# Author: Liam Piper-Brandon
# Version: 1.1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-02
# Description: Shared ErisLITE runtime logging configuration.

"""
ErisLITE v1.1
Centralized application logging.
"""

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from erislite.config.settings import LOG_DIR

LOG_FILE = LOG_DIR / "erislite.log"

DEFAULT_LOG_LEVEL = logging.INFO

LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"

DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


_logging_configured = False


def configure_logging(
    level: int = DEFAULT_LOG_LEVEL,
    log_file: Path = LOG_FILE,
) -> None:
    """
    Configure ErisLITE application logging.

    Safe to call multiple times.
    """

    global _logging_configured

    if _logging_configured:
        return

    log_file.parent.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        LOG_FORMAT,
        datefmt=DATE_FORMAT,
    )

    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=2_000_000,
        backupCount=3,
        encoding="utf-8",
    )

    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)

    root_logger = logging.getLogger("erislite")
    root_logger.setLevel(level)
    root_logger.addHandler(file_handler)
    root_logger.propagate = False

    _logging_configured = True


def get_logger(name: str) -> logging.Logger:
    """
    Return a namespaced ErisLITE logger.
    """

    configure_logging()

    if name.startswith("erislite"):
        return logging.getLogger(name)

    return logging.getLogger(f"erislite.{name}")
